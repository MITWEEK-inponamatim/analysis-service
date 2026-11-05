"""Isolated file-analysis worker (internal only).

Runs in its own container: non-root, no internet network, CPU/memory/pid limits, read-only
filesystem with a tmpfs for scratch files. It exposes one endpoint:
``POST /internal/v1/analyze/application``.
Request bodies are raw bytes; the response is the extractor result (never a verdict).
"""

import asyncio
import hmac
import json
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, status

from .apk_extract import ArchiveLimitExceeded, extract_apk_features
from .apk_signature import verify_signature
from .virustotal import check_hash, compute_sha256
from .yara_scanner import scan_decompiled

MAX_BODY_BYTES = int(os.getenv("WORKER_MAX_BODY_MB", "52")) << 20
MAX_JSON_BODY_BYTES = MAX_BODY_BYTES * 2 + (1 << 20)
MAX_CONCURRENCY = int(os.getenv("WORKER_MAX_CONCURRENCY", "2"))
TIMEOUTS = {
    "application": float(os.getenv("WORKER_APK_TIMEOUT_SECONDS", "150")),
}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if len(os.getenv("FILE_WORKER_SERVICE_KEY", "")) < 32:
        raise RuntimeError(
            "FILE_WORKER_SERVICE_KEY is missing or too short. Run the README step 5 PowerShell "
            "block to derive it from SERVICE_API_KEY, then restart this container."
        )
    yield


app = FastAPI(title="ThreatLens File Worker", version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
semaphore = asyncio.Semaphore(MAX_CONCURRENCY)


def require_worker_key(supplied: str | None) -> None:
    expected = os.getenv("FILE_WORKER_SERVICE_KEY", "")
    if not expected or not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")


async def read_limited_body(request: Request, max_bytes: int | None = None) -> bytes:
    max_bytes = MAX_BODY_BYTES if max_bytes is None else max_bytes
    declared = request.headers.get("content-length", "")
    if declared.isdecimal() and int(declared) > max_bytes:
        raise HTTPException(status_code=413, detail="payload_too_large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > max_bytes:
            raise HTTPException(status_code=413, detail="payload_too_large")
    if not body:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="empty_payload")
    return bytes(body)

async def read_limited_json(request: Request, max_bytes: int | None = None) -> dict[str, Any]:
    max_bytes = MAX_JSON_BODY_BYTES if max_bytes is None else max_bytes
    try:
        payload = json.loads((await read_limited_body(request, max_bytes)).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_json") from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_json")
    return payload


async def run_extraction(kind: str, data: bytes) -> dict[str, Any]:
    async with semaphore:
        try:
            return await asyncio.wait_for(asyncio.to_thread(extract_apk_features, data), timeout=TIMEOUTS[kind])
        except ArchiveLimitExceeded as error:
            return {"available": False, "reason": error.reason, "features": {}, "incomplete_reasons": [error.reason], "details": error.details}
        except asyncio.TimeoutError:
            return {"available": False, "reason": "extraction_timeout", "features": {}, "incomplete_reasons": ["extraction_timeout"]}
        except HTTPException:
            raise
        except Exception:
            return {"available": False, "reason": "extraction_failed", "features": {}, "incomplete_reasons": ["extraction_failed"]}


@app.get("/internal/v1/health")
async def health(x_service_key: str | None = Header(default=None)):
    require_worker_key(x_service_key)
    return {"status": "ok", "concurrency": MAX_CONCURRENCY}



@app.post("/internal/v1/analyze/application")
async def analyze_application(request: Request, x_service_key: str | None = Header(default=None)):
    require_worker_key(x_service_key)
    return await run_extraction("application", await read_limited_body(request))


@app.post("/internal/v1/apk/decompile")
async def decompile_apk_endpoint(request: Request, x_service_key: str | None = Header(default=None)):
    """NEW: Decompile APK using jadx-cli."""
    require_worker_key(x_service_key)
    
    data = await read_limited_body(request)
    
    from .jadx_decompile import decompile_apk
    
    async with semaphore:
        try:
            result = await asyncio.wait_for(decompile_apk(data, timeout=60), timeout=70)
            return result
        except asyncio.TimeoutError:
            return {
                "manifest": {},
                "package_name": "unknown",
                "classes": [],
                "native_libs": {},
                "key_sources": {},
                "code_patterns": {},
                "api_calls": {},
                "extracted_urls": [],
                "obfuscation_detected": False,
                "code_index": {},
                "error": "decompilation_timeout",
            }
        except Exception as e:
            return {
                "manifest": {},
                "package_name": "unknown",
                "classes": [],
                "native_libs": {},
                "key_sources": {},
                "code_patterns": {},
                "api_calls": {},
                "extracted_urls": [],
                "obfuscation_detected": False,
                "code_index": {},
                "error": str(e)[:200],
            }

@app.post("/internal/v1/apk/signature")
async def verify_apk_signature(request: Request, x_service_key: str | None = Header(default=None)):
    """Verify APK signature and extract certificate info."""
    require_worker_key(x_service_key)
    data = await read_limited_body(request)
    try:
        async with semaphore:
            return await asyncio.wait_for(asyncio.to_thread(verify_signature, data), timeout=30)
    except asyncio.TimeoutError:
        return {"signed": False, "certificates": [], "error": "signature_timeout"}
    except Exception as error:
        return {"signed": False, "certificates": [], "error": str(error)[:200]}


@app.post("/internal/v1/apk/virustotal")
async def check_virustotal(request: Request, x_service_key: str | None = Header(default=None)):
    """Check APK hash against VirusTotal."""
    require_worker_key(x_service_key)
    body = await read_limited_json(request)
    sha256 = body.get("sha256", "")
    api_key = body.get("api_key", "") or os.getenv("VIRUSTOTAL_API_KEY", "")
    if not sha256:
        return {"found": False, "error": "missing_sha256"}
    try:
        result = await check_hash(sha256, api_key, timeout=15)
        return result
    except Exception as e:
        return {"found": False, "error": str(e)}


@app.post("/internal/v1/apk/yara")
async def scan_with_yara(request: Request, x_service_key: str | None = Header(default=None)):
    """Scan APK bytes and decompiled source with YARA rules."""
    require_worker_key(x_service_key)
    body = await read_limited_json(request)
    try:
        apk_bytes = bytes.fromhex(body.get("apk_hex", ""))
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_apk_data") from error
    if not apk_bytes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing_apk_data")
    try:
        async with semaphore:
            return await asyncio.to_thread(scan_decompiled, body.get("decompiled", {}), apk_bytes)
    except Exception as error:
        return {"matches": [], "total_matches": 0, "families": [], "max_severity": "low", "error": str(error)[:200]}
