"""Exa search client for claim verification (optional, handoff 7.5).

Search results are *evidence to review*, never proof that a claim is true or false. The
caller records them as findings with ``confidence="low"`` plus a limitation.
"""

import os
from typing import Any

import httpx

from .resilience import json_request, call_with_retry

API_URL = "https://api.exa.ai/search"


def api_key() -> str:
    return os.getenv("EXA_API_KEY", "")


def available() -> bool:
    return bool(api_key())


async def search(claims: str, num_results: int = 3) -> dict[str, Any] | None:
    """Search the web for the given claims. Returns None when Exa is not configured or failed."""
    query = (claims or "").strip()
    if not api_key() or len(query) < 3:
        return None
    payload = {
        "query": query[:500],
        "numResults": max(1, min(num_results, 5)),
        "type": "auto",
        "contents": {"text": {"maxCharacters": 700}},
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(12, connect=5), headers={"x-api-key": api_key()}) as client:
            response = await json_request(client, "POST", API_URL, json=payload)
            body = response.json()
    except Exception:
        return None
    results = []
    for item in (body.get("results") or [])[:5]:
        results.append({
            "title": str(item.get("title") or "")[:200],
            "url": str(item.get("url") or "")[:500],
            "text": str(item.get("text") or item.get("summary") or "")[:600],
            "published": str(item.get("publishedDate") or "")[:40],
        })
    return {"available": True, "query": query[:200], "results": results}
