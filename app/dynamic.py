"""Optional dynamic (sandbox) analysis for APKs (Fase 4, handoff 7.5a).

Running an APK requires an isolated emulator/VM that this deployment does not ship. The
integration is therefore a client for an operator-provided sandbox: when
``DYNAMIC_ANALYSIS_URL`` is not configured the scan records ``dynamic_analysis`` as
unavailable instead of pretending the sample was executed.
"""

import os
from typing import Any

import httpx

from .resilience import json_request

SUMMARY_KEYS = ("network", "sms", "overlay", "install", "files", "processes", "permissions", "calls")


def config() -> tuple[str, str] | None:
    base = os.getenv("DYNAMIC_ANALYSIS_URL", "").strip().rstrip("/")
    key = os.getenv("DYNAMIC_ANALYSIS_API_KEY", "").strip()
    if not base:
        return None
    return base, key


def available() -> bool:
    return config() is not None


def _timeout() -> float:
    try:
        value = float(os.getenv("DYNAMIC_ANALYSIS_TIMEOUT_SECONDS", "180"))
    except ValueError:
        value = 180.0
    return max(30.0, min(value, 900.0))


def summarize(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("summary") if isinstance(payload.get("summary"), dict) else payload
    summary: dict[str, Any] = {}
    for key in SUMMARY_KEYS:
        value = (data or {}).get(key)
        if value in (None, "", [], {}, False):
            continue
        if isinstance(value, list):
            summary[key] = [str(item)[:200] for item in value[:20]]
        elif isinstance(value, bool):
            summary[key] = value
        elif isinstance(value, dict):
            summary[key] = {str(k)[:60]: str(v)[:200] for k, v in list(value.items())[:20]}
        else:
            summary[key] = str(value)[:300]
    return summary


async def analyze_sample(data: bytes, filename: str) -> dict[str, Any] | None:
    """Submit a sample to the configured sandbox. Returns None when unavailable or failed."""
    settings = config()
    if not settings or not data:
        return None
    base, key = settings
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(_timeout(), connect=5), headers=headers) as client:
            response = await json_request(
                client,
                "POST",
                f"{base}/api/v1/analyze",
                files={"file": (filename or "sample.apk", data, "application/vnd.android.package-archive")},
            )
            payload = response.json()
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return {"available": True, "summary": summarize(payload)}
