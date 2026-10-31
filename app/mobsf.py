"""Optional MobSF client for deeper APK static analysis (handoff 7.5a).

MobSF is a separate service; when it is not configured the caller records ``mobsf`` in
``checks_unavailable``. The sample is only sent when the user granted
``consent_external_upload`` because it leaves our infrastructure.
"""

import json
import os
import time
from typing import Any

import httpx

from .resilience import call_with_retry

SUMMARY_FIELDS = (
    "app_name", "package_name", "version_name", "min_sdk", "target_sdk",
    "permissions", "activities", "services", "receivers", "providers",
    "urls", "secrets", "firebase_urls", "http_urls", "browsable_activities",
    "exported_activities", "certificate_analysis", "hardcoded_secrets",
    "malware_permissions", "dangerous_permissions",
)


def config() -> tuple[str, str] | None:
    base = os.getenv("MOBSF_URL", "").strip().rstrip("/")
    key = os.getenv("MOBSF_API_KEY", "").strip()
    if not base or not key:
        return None
    return base, key


def available() -> bool:
    return config() is not None


def _timeout() -> float:
    try:
        value = float(os.getenv("MOBSF_TIMEOUT_SECONDS", "120"))
    except ValueError:
        value = 120.0
    return max(15.0, min(value, 600.0))


def summarize(report: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for field in SUMMARY_FIELDS:
        value = report.get(field)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            summary[field] = [str(item)[:200] for item in value[:40]]
        elif isinstance(value, dict):
            summary[field] = json.loads(json.dumps(value)[:4000])
        else:
            summary[field] = str(value)[:400]
    return summary


async def analyze_sample(data: bytes, filename: str) -> dict[str, Any] | None:
    """Upload, scan, and fetch a report summary. Returns None when MobSF is unavailable."""
    settings = config()
    if not settings or not data:
        return None
    base, key = settings
    timeout = _timeout()
    headers = {"Authorization": key}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=5), headers=headers) as client:
            async def upload() -> dict[str, Any]:
                response = await client.post(
                    f"{base}/api/v1/upload",
                    files={"file": (filename or "sample.apk", data, "application/vnd.android.package-archive")},
                )
                response.raise_for_status()
                return response.json()

            uploaded = await call_with_retry(upload, name="mobsf.upload")
            sample_hash = str(uploaded.get("hash") or "")
            if not sample_hash:
                return None

            async def scan() -> None:
                response = await client.post(
                    f"{base}/api/v1/scan",
                    data={"hash": sample_hash, "re_scan": "0"},
                    headers={"Authorization": key},
                )
                response.raise_for_status()

            started = time.monotonic()
            try:
                await call_with_retry(scan, name="mobsf.scan", attempts=1)
            except Exception:
                # MobSF may reject the re-scan of an already-scanned hash; the report may still exist.
                if time.monotonic() - started >= timeout:
                    return None

            async def report() -> dict[str, Any]:
                response = await client.get(f"{base}/api/v1/report_json", params={"hash": sample_hash})
                response.raise_for_status()
                return response.json()

            payload = await call_with_retry(report, name="mobsf.report", attempts=2)
    except Exception:
        return None
    return {"available": True, "hash": sample_hash, "summary": summarize(payload or {})}
