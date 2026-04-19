"""MCP search tool — semantic search over Qdrant."""
import os
from agents.rag.retriever import retrieve


def search_vulnerabilities(query: str) -> dict:
    docs = retrieve(query, collections=["cve_descriptions", "exploit_reports"], top_k=10)
    return {"results": docs}
