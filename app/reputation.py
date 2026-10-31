"""URL reputation lookups shared by the URL scanner and the ``check_url_reputation`` tool.

Both providers are optional. ``None`` means "check did not run" so callers record it in
``checks_unavailable`` instead of assuming the URL is clean (handoff 7.5).
"""

import base64
import os

import httpx

from .resilience import json_request
from .risk import finding
from .schemas import Finding

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"


def safe_browsing_available() -> bool:
    return bool(os.getenv("SAFE_BROWSING_API_KEY"))


def virustotal_available() -> bool:
    return bool(os.getenv("VIRUSTOTAL_API_KEY"))


async def safe_browsing(url: str) -> list[Finding] | None:
    if not safe_browsing_available():
        return None
    body = {
        "client": {"clientId": "threatlens", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await json_request(client, "POST", SAFE_BROWSING_URL, params={"key": os.environ["SAFE_BROWSING_API_KEY"]}, json=body)
            matches = response.json().get("matches") or []
    except Exception:
        return None
    if matches:
        return [finding("URL terdaftar sebagai ancaman oleh Google Safe Browsing.", "safe_browsing", "high", {"matches": len(matches)})]
    return []


async def virustotal(url: str) -> list[Finding] | None:
    if not virustotal_available():
        return None
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        async with httpx.AsyncClient(timeout=8, headers={"x-apikey": os.environ["VIRUSTOTAL_API_KEY"]}) as client:
            response = await json_request(client, "GET", f"{VIRUSTOTAL_URL}/{url_id}")
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    except Exception:
        return None
    malicious = int(stats.get("malicious", 0) or 0)
    if malicious > 0:
        return [finding(f"VirusTotal melaporkan {malicious} deteksi berbahaya untuk URL ini.", "virustotal", "high", {"malicious_engines": malicious})]
    return []
