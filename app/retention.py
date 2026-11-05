"""Scheduled deletion of expired uploads (handoff 2.4).

Rows become eligible when ``files.expires_at`` passes. The object is removed from the private
bucket first, then the metadata row, so a storage failure never hides the file record.
"""

import asyncio
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger("threatlens.retention")

DEFAULT_INTERVAL_SECONDS = 3600
DEFAULT_BATCH = 200


def _supabase() -> tuple[str, str] | None:
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    secret = os.getenv("SUPABASE_SECRET_KEY", "")
    if not url or not secret:
        return None
    return url, secret


def enabled() -> bool:
    if os.getenv("RETENTION_ENABLED", "true").strip().lower() in {"0", "false", "no"}:
        return False
    return _supabase() is not None


def interval_seconds() -> int:
    try:
        value = int(os.getenv("RETENTION_INTERVAL_SECONDS", str(DEFAULT_INTERVAL_SECONDS)))
    except ValueError:
        value = DEFAULT_INTERVAL_SECONDS
    return max(60, value)


async def purge_expired(limit: int = DEFAULT_BATCH, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
    """Delete expired objects and their rows. Returns a small report; never raises."""
    config = _supabase()
    if config is None:
        return {"status": "skipped", "reason": "supabase_not_configured", "rows": 0, "objects": 0}
    base, secret = config
    headers = {"apikey": secret, "Authorization": f"Bearer {secret}"}
    now = datetime.now(timezone.utc).isoformat()
    summary: dict[str, Any] = {"status": "ok", "rows": 0, "objects": 0, "storage_failed": 0}
    started = datetime.now(timezone.utc)
    try:
        own_client = client is None
        http = client or httpx.AsyncClient(timeout=httpx.Timeout(20, connect=5))
        try:
            response = await http.get(
                f"{base}/rest/v1/files",
                params={"select": "id,bucket,storage_path", "expires_at": f"lt.{now}", "limit": str(max(1, min(limit, 1000)))},
                headers=headers,
            )
            response.raise_for_status()
            rows = response.json()
            if not isinstance(rows, list):
                raise ValueError("invalid_files_response")
            if rows:
                grouped: dict[str, list[str]] = defaultdict(list)
                for row in rows:
                    grouped[str(row.get("bucket") or "uploads")].append(str(row.get("storage_path") or ""))
                for bucket, paths in grouped.items():
                    payload = [path for path in paths if path]
                    if not payload:
                        continue
                    removal = await http.request(
                        "DELETE",
                        f"{base}/storage/v1/object/{bucket}",
                        headers={**headers, "Content-Type": "application/json"},
                        json={"prefixes": payload},
                    )
                    if removal.status_code < 300:
                        summary["objects"] += len(payload)
                    else:
                        summary["storage_failed"] += len(payload)
                        logger.warning("retention could not delete %d object(s) from %s", len(payload), bucket)
                deleted_ids = [str(row["id"]) for row in rows]
                purge = await http.delete(
                    f"{base}/rest/v1/files",
                    params={"id": f"in.({','.join(deleted_ids)})"},
                    headers=headers,
                )
                if purge.status_code < 300:
                    summary["rows"] = len(deleted_ids)
                else:
                    logger.warning("retention could not delete %d file row(s)", len(deleted_ids))

            summary["evidence_rows"] = 0
            for table in ("scan_evidence_items", "scan_evidence"):
                purge = await http.delete(
                    f"{base}/rest/v1/{table}",
                    params={"expires_at": f"lt.{now}", "select": "id"},
                    headers={**headers, "Prefer": "return=representation"},
                )
                if purge.status_code < 300:
                    deleted = purge.json() if purge.content else []
                    summary["evidence_rows"] += len(deleted) if isinstance(deleted, list) else 0
                else:
                    summary["status"] = "partial"
                    logger.warning("retention could not purge expired %s rows", table)
        finally:
            if own_client:
                await http.aclose()
    except Exception as error:  # pragma: no cover - defensive
        logger.warning("retention run failed: %s", type(error).__name__)
        summary["status"] = "failed"
        summary["reason"] = type(error).__name__
    finally:
        summary["duration_ms"] = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    return summary


async def retention_loop() -> None:
    """Background task: purge expired files on an interval until cancelled."""
    interval = interval_seconds()
    logger.info("retention loop started (interval %ds)", interval)
    try:
        while True:
            await asyncio.sleep(interval)
            result = await purge_expired()
            try:
                from .metrics import metrics

                metrics.inc("retention_runs", status=str(result.get("status", "unknown")))
            except Exception:
                pass
            if result.get("rows") or result.get("objects"):
                logger.info("retention removed %d row(s) and %d object(s)", result.get("rows", 0), result.get("objects", 0))
    except asyncio.CancelledError:  # pragma: no cover - shutdown path
        logger.info("retention loop stopped")
        raise
