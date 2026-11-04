"""Client for the isolated file-analysis worker.

The API process never parses untrusted APK bytes itself when the worker is
configured: bytes are POSTed to ``analysis-worker`` (no internet, non-root, CPU/memory
limited). Without ``FILE_WORKER_URL`` (local development, unit tests) the same extractor
runs in-process so behaviour stays observable.
"""

import asyncio
import os

import httpx

from .apk_extract import ArchiveLimitExceeded, extract_apk_features
from .file_auth import file_service_key

DEFAULT_TIMEOUTS = {"application": 180}


def _timeout(kind: str) -> float:
    configured = os.getenv("FILE_WORKER_TIMEOUT_SECONDS", "")
    if configured.isdigit() and int(configured) > 0:
        return float(configured)
    return float(DEFAULT_TIMEOUTS.get(kind, 90))


def _local_extract(data: bytes) -> dict:
    try:
        return extract_apk_features(data)
    except ArchiveLimitExceeded as error:
        return {"available": False, "reason": error.reason, "features": {}, "incomplete_reasons": [error.reason]}
    except Exception:
        return {"available": False, "reason": "extraction_failed", "features": {}, "incomplete_reasons": ["extraction_failed"]}


async def analyze_file(kind: str, data: bytes, filename: str = "", mime: str = "") -> dict:
    """Run static extraction for one uploaded object.

    Returns a dict with at least ``available`` and ``reason``. Never raises: a failed
    extractor becomes ``available: False`` so the report can record it as unavailable
    instead of losing the whole scan.
    """
    base = os.getenv("FILE_WORKER_URL", "").strip().rstrip("/")
    if not base:
        return await asyncio.to_thread(_local_extract, data)
    service_key = os.getenv("SERVICE_API_KEY", "")
    if not service_key:
        return {"available": False, "reason": "worker_key_missing", "features": {}, "incomplete_reasons": ["worker_key_missing"]}
    headers = {
        "X-Service-Key": file_service_key(service_key),
        "Content-Type": mime or "application/octet-stream",
        "X-Original-Filename": filename[:200],
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(_timeout(kind), connect=5)) as client:
            response = await client.post(f"{base}/internal/v1/analyze/{kind}", headers=headers, content=data)
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPStatusError as error:
        reason = "worker_rejected" if error.response.status_code in (400, 413, 422) else "file_worker_unavailable"
        return {"available": False, "reason": reason, "features": {}, "incomplete_reasons": [reason]}
    except Exception:
        return {"available": False, "reason": "file_worker_unavailable", "features": {}, "incomplete_reasons": ["file_worker_unavailable"]}
    if not isinstance(payload, dict) or "available" not in payload:
        return {"available": False, "reason": "invalid_worker_response", "features": {}, "incomplete_reasons": ["invalid_worker_response"]}
    return payload


async def decompile_apk_via_worker(data: bytes) -> dict:
    """
    Decompile APK using jadx via file worker.
    
    Returns decompiled dict with manifest, classes, code_patterns, etc.
    Never raises: failed decompilation returns empty dict.
    """
    base = os.getenv("FILE_WORKER_URL", "").strip().rstrip("/")
    if not base:
        # Local fallback: run jadx directly (requires jadx in PATH)
        from .jadx_decompile import decompile_apk
        try:
            return await decompile_apk(data, timeout=60)
        except Exception:
            return {}
    
    service_key = os.getenv("SERVICE_API_KEY", "")
    if not service_key:
        return {}
    
    headers = {
        "X-Service-Key": file_service_key(service_key),
        "Content-Type": "application/vnd.android.package-archive",
    }
    
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(70, connect=5)) as client:
            response = await client.post(f"{base}/internal/v1/apk/decompile", headers=headers, content=data)
            response.raise_for_status()
            payload = response.json()
            return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


async def verify_apk_signature_via_worker(data: bytes) -> dict:
    """Call worker to verify APK signature."""
    base = os.getenv("FILE_WORKER_URL", "").strip().rstrip("/")
    if not base:
        from .apk_signature import verify_signature
        return verify_signature(data)
    
    url = f"{base}/internal/v1/apk/signature"
    headers = {"X-Service-Key": file_service_key()}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, content=data, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {"signed": False, "certificates": [], "error": "worker_unavailable"}


async def check_virustotal_via_worker(sha256: str) -> dict:
    """Call worker to check VirusTotal."""
    base = os.getenv("FILE_WORKER_URL", "").strip().rstrip("/")
    if not base:
        from .virustotal import check_hash
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        return await check_hash(sha256, api_key, timeout=10)
    
    url = f"{base}/internal/v1/apk/virustotal"
    headers = {"X-Service-Key": file_service_key(), "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(url, json={"sha256": sha256}, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {"found": False, "error": "worker_unavailable"}


async def scan_yara_via_worker(apk_bytes: bytes, decompiled: dict) -> dict:
    """Call worker to scan with YARA."""
    base = os.getenv("FILE_WORKER_URL", "").strip().rstrip("/")
    if not base:
        from .yara_scanner import scan_decompiled
        return scan_decompiled(decompiled, apk_bytes)
    
    url = f"{base}/internal/v1/apk/yara"
    headers = {"X-Service-Key": file_service_key(), "Content-Type": "application/json"}
    apk_hex = apk_bytes.hex()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json={"apk_hex": apk_hex, "decompiled": decompiled}, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {"matches": [], "total_matches": 0, "families": [], "max_severity": "low", "error": "worker_unavailable"}
