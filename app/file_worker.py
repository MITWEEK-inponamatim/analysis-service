"""Isolated file-analysis worker (internal only).

Runs in its own container: non-root, no internet network, CPU/memory/pid limits, read-only
filesystem with a tmpfs for scratch files. It exposes one endpoint:
``POST /internal/v1/analyze/application``.
Request bodies are raw bytes; the response is the extractor result (never a verdict).
"""

import asyncio
import hmac
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, status

from .apk_extract import ArchiveLimitExceeded, extract_apk_features

MAX_BODY_BYTES = int(os.getenv("WORKER_MAX_BODY_MB", "52")) << 20
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


async def read_limited_body(request: Request) -> bytes:
    declared = request.headers.get("content-length", "")
    if declared.isdecimal() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="payload_too_large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="payload_too_large")
    if not body:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="empty_payload")
    return bytes(body)


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
