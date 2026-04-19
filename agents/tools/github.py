"""
GitHub tool — fetch source files from a repository.
Used by the triage agent to find files importing a vulnerable package.
"""
import os
import base64
import requests
from typing import Optional


def fetch_file(repo: str, package_name: str) -> list[dict]:
    """
    Search for files in a GitHub repo that import the given package.
    Returns a list of {path, content} dicts.

    Uses the GitHub Search API (code search) to find relevant files.
    Falls back to an empty list if the repo is not searchable.
    """
    token = os.getenv("GITHUB_TOKEN", "")
    headers = {
        "Accept": "application/vnd.github.v3+json",
        **({"Authorization": f"Bearer {token}"} if token else {}),
    }

    query = f"{package_name} repo:{repo}"
    resp = requests.get(
        "https://api.github.com/search/code",
        params={"q": query, "per_page": 5},
        headers=headers,
        timeout=10,
    )

    if resp.status_code != 200:
        return []

    files = []
    for item in resp.json().get("items", [])[:3]:
        content_resp = requests.get(item["url"], headers=headers, timeout=10)
        if content_resp.status_code == 200:
            raw = content_resp.json().get("content", "")
            try:
                content = base64.b64decode(raw).decode("utf-8", errors="replace")
            except Exception:
                content = raw
            files.append({"path": item["path"], "content": content[:4000]})

    return files
