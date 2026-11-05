"""VirusTotal API v3 client for APK reputation and optional sample upload."""

import asyncio
import hashlib
import os
from typing import Any

import httpx


API_BASE = "https://www.virustotal.com/api/v3"
MAX_UPLOAD_BYTES = 32 << 20


def api_key() -> str:
    return os.getenv("VIRUSTOTAL_API_KEY", "").strip()


async def check_hash(sha256: str, api_key_value: str, timeout: int = 10) -> dict[str, Any]:
    """Query one SHA-256 and return a JSON-safe normalized result."""
    if not api_key_value:
        return {"found": False, "error": "no_api_key"}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"{API_BASE}/files/{sha256}", headers={"x-apikey": api_key_value})
        if response.status_code == 404:
            return {"found": False}
        if response.status_code != 200:
            return {"found": False, "error": f"http_{response.status_code}"}
        attrs = response.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})
        names = sorted({
            result.get("result")
            for result in results.values()
            if result.get("category") == "malicious" and result.get("result")
        })
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total": sum(stats.values()),
            "engines": sum(stats.values()),
            "first_seen": attrs.get("first_submission_date", 0),
            "last_analysis": attrs.get("last_analysis_date", 0),
            "names": names,
            "vendors": {
                vendor: {"category": result.get("category", "undetected"), "result": result.get("result") or ""}
                for vendor, result in results.items()
            },
        }
    except (asyncio.TimeoutError, httpx.TimeoutException):
        return {"found": False, "error": "timeout"}
    except Exception as error:
        return {"found": False, "error": str(error)}


async def lookup_file_hash(sha256: str) -> dict[str, Any] | None:
    """Lookup using configured credentials; None means provider unavailable."""
    result = await check_hash(sha256, api_key(), timeout=15)
    return None if result.get("error") == "no_api_key" else result


async def upload_sample(data: bytes, filename: str) -> dict[str, Any] | None:
    """Upload a sample only when explicitly enabled by the caller."""
    if not api_key() or not data or len(data) > MAX_UPLOAD_BYTES:
        return None
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=10)) as client:
            response = await client.post(
                f"{API_BASE}/files/upload",
                headers={"x-apikey": api_key()},
                files={"file": (filename or "sample.apk", data, "application/vnd.android.package-archive")},
            )
        if response.status_code not in {200, 201}:
            return None
        return response.json()
    except Exception:
        return None


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
