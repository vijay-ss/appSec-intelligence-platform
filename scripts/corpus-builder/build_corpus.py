"""
Corpus Builder
==============
Indexes vulnerability data into Qdrant so the RAG retriever has something to search.

Run once after initial OSV bulk load, and again periodically to pick up new CVEs.
Typically scheduled weekly or run manually after a large batch of new CVEs.

Usage:
    python scripts/corpus-builder/build_corpus.py

Collections created / updated:
    cve_descriptions  — CVE description text from PostgreSQL vulnerabilities table
    exploit_reports   — Placeholder for threat intelligence / exploit POC summaries
                        (extend this to pull from NVD, GitHub Security Advisories, etc.)

Environment variables (same as rest of platform, reads from .env):
    POSTGRES_URL
    QDRANT_URL
    LLM_PROVIDER + embedding model vars (OLLAMA_EMBED_MODEL or OPENAI_API_KEY)
"""
from __future__ import annotations

import logging
import os
import sys
import time
from typing import Iterator

import psycopg2
import psycopg2.extras
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    PointStruct,
    VectorParams,
)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from appsec_shared.config import settings
from appsec_shared.logging import configure_logging

log = configure_logging("corpus-builder")

BATCH_SIZE = 100
EMBED_DIM_OLLAMA = 768
EMBED_DIM_OPENAI = 3072


def get_embeddings():
    """Return the configured embeddings model (same as agents/llm_provider.py)."""
    if settings.llm_provider == "anthropic":
        from langchain_openai import OpenAIEmbeddings
        return OpenAIEmbeddings(
            model="text-embedding-3-large",
            openai_api_key=settings.openai_api_key,
        )
    else:
        from langchain_ollama import OllamaEmbeddings
        return OllamaEmbeddings(
            model=settings.ollama_embed_model,
            base_url=settings.ollama_base_url,
        )


def embed_dim() -> int:
    return EMBED_DIM_OPENAI if settings.llm_provider == "anthropic" else EMBED_DIM_OLLAMA


def ensure_collection(client: QdrantClient, name: str, dim: int) -> None:
    """Create collection if it doesn't exist."""
    existing = {c.name for c in client.get_collections().collections}
    if name not in existing:
        client.create_collection(
            collection_name=name,
            vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
        )
        log.info("collection_created", collection=name, dim=dim)
    else:
        log.info("collection_exists", collection=name)


def upsert_batch(
    client: QdrantClient,
    collection: str,
    embeddings_model,
    docs: list[dict],
) -> None:
    """Embed a batch of documents and upsert into Qdrant."""
    texts = [d["text"] for d in docs]
    vectors = embeddings_model.embed_documents(texts)

    points = [
        PointStruct(
            id=doc["id"],
            vector=vector,
            payload={k: v for k, v in doc.items() if k != "id"},
        )
        for doc, vector in zip(docs, vectors)
    ]
    client.upsert(collection_name=collection, points=points)
    log.info("upserted_batch", collection=collection, count=len(points))


def iter_cve_descriptions(conn) -> Iterator[dict]:
    """
    Yield one document per CVE from the PostgreSQL vulnerabilities table.
    Text is a combination of CVE ID, package, severity, and description
    giving the embedding model enough context to retrieve relevant CVEs
    for a query like "auth bypass in requests library".
    """
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute("""
            SELECT
                cve_id,
                affected_package,
                ecosystem,
                severity_tier,
                cvss_score,
                description,
                affected_version_range,
                safe_version
            FROM vulnerabilities
            WHERE description != ''
            ORDER BY published_at DESC
        """)
        for i, row in enumerate(cur):
            text = (
                f"{row['cve_id']}: {row['affected_package']} ({row['ecosystem']}) "
                f"severity={row['severity_tier']} cvss={row['cvss_score']}. "
                f"Affected: {row['affected_version_range']}. "
                f"Safe version: {row['safe_version'] or 'unknown'}. "
                f"{row['description']}"
            )
            yield {
                "id": i + 1,
                "text": text,
                "cve_id": row["cve_id"],
                "package": row["affected_package"],
                "ecosystem": row["ecosystem"],
                "severity": row["severity_tier"],
            }
    
    
def iter_triage_reports(conn) -> Iterator[dict]:
    """
    Yield one document per triage report so past analysis is searchable.
    Enables the MCP search_vulnerabilities tool to find reports by natural language.
    """
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute("""
            SELECT
                report_id,
                cve_id,
                service_id,
                exploitability_verdict,
                exploitability_rationale,
                blast_radius_tier,
                blast_radius_rationale,
                remediation_action
            FROM triage_reports
            ORDER BY generated_at DESC
        """)
        for i, row in enumerate(cur):
            text = (
                f"Triage report for {row['cve_id']} in {row['service_id']}. "
                f"Verdict: {row['exploitability_verdict']}. "
                f"Blast radius: {row['blast_radius_tier']}. "
                f"{row['exploitability_rationale']} "
                f"Remediation: {row['remediation_action']}"
            )
            yield {
                "id": i + 1,
                "text": text,
                "report_id": row["report_id"],
                "cve_id": row["cve_id"],
                "service_id": row["service_id"],
                "verdict": row["exploitability_verdict"],
            }


def build_corpus() -> None:
    log.info("corpus_build_started", llm_provider=settings.llm_provider)
    for key, value in os.environ.items():
        print(f"{key}: {value}")
    print(settings.postgres_url)

    embeddings = get_embeddings()
    dim = embed_dim()

    client = QdrantClient(url=settings.qdrant_url)
    conn = psycopg2.connect(settings.postgres_url)

    try:
        ensure_collection(client, "cve_descriptions", dim)
        ensure_collection(client, "triage_reports", dim)

        log.info("indexing_cve_descriptions")
        batch: list[dict] = []
        total = 0
        for doc in iter_cve_descriptions(conn):
            batch.append(doc)
            if len(batch) >= BATCH_SIZE:
                upsert_batch(client, "cve_descriptions", embeddings, batch)
                total += len(batch)
                batch = []
                time.sleep(0.1)  # Ollama rate limit
        if batch:
            upsert_batch(client, "cve_descriptions", embeddings, batch)
            total += len(batch)
        log.info("cve_descriptions_indexed", total=total)

        log.info("indexing_triage_reports")
        batch = []
        total = 0
        for doc in iter_triage_reports(conn):
            batch.append(doc)
            if len(batch) >= BATCH_SIZE:
                upsert_batch(client, "triage_reports", embeddings, batch)
                total += len(batch)
                batch = []
                time.sleep(0.1)
        if batch:
            upsert_batch(client, "triage_reports", embeddings, batch)
            total += len(batch)
        log.info("triage_reports_indexed", total=total)

    finally:
        conn.close()

    log.info("corpus_build_complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    build_corpus()