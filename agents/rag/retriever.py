"""
RAG Retriever — semantic search over Qdrant collections.
"""
import os
from typing import Optional

from qdrant_client import QdrantClient
from qdrant_client.models import SearchRequest

from agents.llm_provider import get_embeddings

_client: Optional[QdrantClient] = None
_embeddings = None


def _get_client() -> QdrantClient:
    global _client
    if _client is None:
        _client = QdrantClient(url=os.getenv("QDRANT_URL", "http://localhost:6333"))
    return _client


def _get_embeddings():
    global _embeddings
    if _embeddings is None:
        _embeddings = get_embeddings()
    return _embeddings


def retrieve(query: str, collections: list[str], top_k: int=5) -> list[dict]:
    """
    Embed the query and search across one or more Qdrant collections.
    Returns a deduplicated list of {content, source, score} dicts.
    """
    client = _get_client()
    embeddings = _get_embeddings()
    
    try:
        vector = embeddings.embed_query(query)
    except Exception:
        return []
    
    results = []
    seen_ids = set()
    
    for collection in collections:
        try:
            hits = client.search(
                collection_name=collection,
                query_vector=vector,
                limit=top_k,
                with_payload=True,
            )
            
            for hit in hits:
                if hit.id not in seen_ids:
                    seen_ids.add(hit.id)
                    results.append({
                        "content": hit.payload.get("content", ""),
                        "source": hit.payload.get("source", collection),
                        "score": hit.score,
                    })
        except Exception:
            continue
    
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:top_k]
