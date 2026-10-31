"""Optional VirusTotal lookups for uploaded files.

Both entry points are best-effort: a missing key or a failed request returns ``None`` and
the caller records the check as unavailable instead of failing the scan (handoff 7.5).
Samples are only uploaded when the user explicitly consented (``consent_external_upload``).
"""

import os
from typing import Any

import httpx

API_BASE = "https://www.virustotal.com/api/v3"
MAX_UPLOAD_BYTES = 32 << 20


def api_key() -> str:
    return os.getenv("VIRUSTOTAL_API_KEY", "")


def _headers() -> dict[str, str]:
    return {"x-apikey": api_key()}


async def lookup_file_hash(sha256: str) -> dict[str, Any] | None:
    if not api_key() or not sha256:
        return None
    try:
        async with httpx.AsyncClient(timeout=10, headers=_headers()) as client:
            response = await client.get(f"{API_BASE}/files/{sha256}")
            if response.status_code == 404:
                return {"found": False, "malicious": 0, "suspicious": 0, "total": 0}
            response.raise_for_status()
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    except Exception:
        return None
    return {
        "found": True,
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "total": sum(int(stats.get(key, 0) or 0) for key in ("malicious", "suspicious", "harmless", "undetected", "timeout", "failure")),
    }


async def upload_sample(data: bytes, filename: str) -> dict[str, Any] | None:
    if not api_key() or not data or len(data) > MAX_UPLOAD_BYTES:
        return None
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60, connect=5), headers=_headers()) as client:
            response = await client.post(
                f"{API_BASE}/files",
                files={"file": (filename or "sample.apk", data, "application/vnd.android.package-archive")},
            )
            response.raise_for_status()
            payload = response.json()
    except Exception:
        return None
    return {"analysis_id": payload.get("data", {}).get("id")}
