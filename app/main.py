import asyncio
import hmac
import importlib.util
import os
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException

from . import phone_reports, retention
from .apk_scanner import scan_application
from .image_scanner import scan_image
from .logs import configure_logging
from .metrics import metrics
from .phone_scanner import normalize_payload, scan_phone
from .risk import fail_report
from .scanners import scan_message, scan_url
from .schemas import JobRequest, PhoneNormalizeRequest, PhoneReportModerationRequest

load_dotenv()


def max_concurrent_jobs() -> int:
    try:
        value = int(os.getenv("MAX_CONCURRENT_JOBS", "4"))
    except ValueError:
        value = 4
    return max(1, min(value, 16))


job_slots = asyncio.Semaphore(max_concurrent_jobs())


@asynccontextmanager
async def lifespan(_app: FastAPI):
    configure_logging()
    task: asyncio.Task | None = None
    if retention.enabled():
        task = asyncio.create_task(retention.retention_loop())
    try:
        yield
    finally:
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass


app = FastAPI(title="ThreatLens Analysis Service", version="1.1.0", lifespan=lifespan)
jobs: dict[str, dict[str, Any]] = {}


def require_service_key(key: str | None):
    expected = os.getenv("SERVICE_API_KEY", "")
    if not expected or not key or not hmac.compare_digest(key, expected):
        raise HTTPException(status_code=401, detail="unauthorized")


async def save_job(job_id: str, row: dict[str, Any]):
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    secret = os.getenv("SUPABASE_SECRET_KEY", "")
    if not url or not secret:
        return
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(f"{url}/rest/v1/analysis_jobs", params={"on_conflict": "job_id"},
            headers={"apikey": secret, "Authorization": f"Bearer {secret}", "Prefer": "resolution=merge-duplicates"},
            json=row)
        response.raise_for_status()


async def update_job(job_id: str, **fields):
    jobs[job_id].update(fields)
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    secret = os.getenv("SUPABASE_SECRET_KEY", "")
    if url and secret:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.patch(f"{url}/rest/v1/analysis_jobs", params={"job_id": f"eq.{job_id}"},
                headers={"apikey": secret, "Authorization": f"Bearer {secret}"},
                json={k: v for k, v in fields.items() if k in {"status", "progress", "report", "error"}})
            response.raise_for_status()


def _payload(report: Any) -> dict[str, Any]:
    return report.model_dump(mode="json") if hasattr(report, "model_dump") else report


async def run_scanner(request: JobRequest) -> Any:
    kind = request.type
    options = request.options or {}
    payload = request.input or {}
    if kind == "message":
        return await scan_message(request.scan_id, str(payload.get("text", "")))
    if kind == "url":
        return await scan_url(request.scan_id, str(payload.get("url", "")), request.user_id)
    if kind == "phone":
        return await scan_phone(request.scan_id, str(payload.get("number", "")), str(payload.get("default_region", "ID")))
    if kind == "image":
        return await scan_image(request.scan_id, request.user_id, payload, options)
    if kind == "application":
        return await scan_application(request.scan_id, request.user_id, payload, options)
    return fail_report(request.scan_id, kind, "scanner_not_implemented", "Scanner not available in this phase.")


async def execute(job_id: str, request: JobRequest):
    started = time.monotonic()
    metrics.inc("jobs_total", type=request.type)
    try:
        await update_job(job_id, status="running", progress=25)
        async with job_slots:
            report = await run_scanner(request)
        payload = _payload(report)
        status = "failed" if payload.get("outcome") == "scan_failed" else "completed"
        await update_job(job_id, status=status, progress=100, report=payload)
        metrics.inc("jobs_finished", type=request.type, status=status)
        metrics.observe("job_seconds", time.monotonic() - started, type=request.type)
    except Exception:
        metrics.inc("jobs_finished", type=request.type, status="errored")
        report = fail_report(request.scan_id, request.type, "analysis_failed", "Analisis gagal karena kesalahan internal pada layanan analisis.")
        try:
            await update_job(job_id, status="failed", progress=100, report=_payload(report), error="analysis_failed")
        except Exception:
            jobs.setdefault(job_id, {}).update({"status": "failed", "progress": 100, "report": _payload(report), "error": "analysis_failed"})


def capabilities() -> dict[str, Any]:
    def installed(module: str) -> bool:
        try:
            return importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            return False

    return {
        "phonenumbers": installed("phonenumbers"),
        "androguard": installed("androguard"),
        "ocr": installed("pytesseract") and installed("PIL"),
        "file_worker": bool(os.getenv("FILE_WORKER_URL", "")),
        "langgraph": installed("langgraph"),
        "checkpointer": bool(os.getenv("DATABASE_URL_SESSION", "")),
        "ic4": bool(os.getenv("IC4_API_URL", "https://api.ic4.id/api/public/link")),
        "malwarebytes": bool(os.getenv("MALWAREBYTES_API_URL", "https://lookup-api.malwarebytes.com/api/v1/lookup/submit")),
        "safe_browsing": bool(os.getenv("SAFE_BROWSING_API_KEY", "")),
        "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY", "")),
        "exa": bool(os.getenv("EXA_API_KEY", "")),
        "mobsf": bool(os.getenv("MOBSF_URL", "") and os.getenv("MOBSF_API_KEY", "")),
        "vision": bool(os.getenv("OPENAI_VISION_MODEL", "")),
        "retention": retention.enabled(),
        "phone_reports": bool(os.getenv("SUPABASE_URL", "") and os.getenv("SUPABASE_SECRET_KEY", "")),
    }


@app.get("/internal/v1/health")
async def health(x_service_key: str | None = Header(default=None)):
    require_service_key(x_service_key)
    return {"status": "ok", "capabilities": capabilities()}


@app.post("/internal/v1/maintenance/retention")
async def run_retention(x_service_key: str | None = Header(default=None)):
    """Manual trigger for the expired-file purge (same code path as the scheduled loop)."""
    require_service_key(x_service_key)
    return await retention.purge_expired()


@app.get("/internal/v1/metrics")
async def get_metrics(x_service_key: str | None = Header(default=None)):
    require_service_key(x_service_key)
    snapshot = metrics.snapshot()
    snapshot["jobs_in_memory"] = len(jobs)
    snapshot["concurrency_limit"] = max_concurrent_jobs()
    return snapshot


@app.post("/internal/v1/phone/normalize")
async def normalize_phone(request: PhoneNormalizeRequest, x_service_key: str | None = Header(default=None)):
    """One normalisation implementation for the whole product (Go stores what this returns)."""
    require_service_key(x_service_key)
    return normalize_payload(request.number, request.default_region)


@app.patch("/internal/v1/phone-reports/{report_id}")
async def moderate_phone_report(report_id: str, request: PhoneReportModerationRequest,
                                x_service_key: str | None = Header(default=None)):
    """Moderation only: ``verified`` reports are the only ones that raise risk."""
    require_service_key(x_service_key)
    if not phone_reports.valid_report_id(report_id):
        raise HTTPException(status_code=400, detail="invalid_report_id")
    try:
        updated = await phone_reports.set_status(report_id, request.status)
    except phone_reports.ReportsUnavailable as error:
        detail = str(error)
        raise HTTPException(status_code=404 if detail == "report_not_found" else 503, detail=detail) from error
    metrics.inc("phone_reports_moderated", status=request.status)
    return updated


@app.post("/internal/v1/jobs", status_code=202)
async def create_job(request: JobRequest, background: BackgroundTasks, x_service_key: str | None = Header(default=None)):
    require_service_key(x_service_key)
    job_id = request.scan_id
    existing = jobs.get(job_id)
    if existing:
        return {"job_id": job_id}
    row = {"job_id": job_id, "scan_id": request.scan_id, "type": request.type, "status": "queued", "progress": 0}
    jobs[job_id] = row
    await save_job(job_id, row)
    background.add_task(execute, job_id, request)
    return {"job_id": job_id}


@app.get("/internal/v1/jobs/{job_id}")
async def get_job(job_id: str, x_service_key: str | None = Header(default=None)):
    require_service_key(x_service_key)
    if job_id in jobs:
        return jobs[job_id]
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    secret = os.getenv("SUPABASE_SECRET_KEY", "")
    if url and secret:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{url}/rest/v1/analysis_jobs", params={"job_id": f"eq.{job_id}", "select": "*"},
                headers={"apikey": secret, "Authorization": f"Bearer {secret}"})
            if response.is_success and response.json():
                job = response.json()[0]
                jobs[job_id] = job
                return job
    raise HTTPException(status_code=404, detail="job_not_found")
