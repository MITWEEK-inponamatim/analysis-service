"""Persist scan evidence to Supabase for audit and analysis."""
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx


def _config() -> tuple[str, str] | None:
    supabase_url = os.getenv("SUPABASE_URL", "").rstrip("/")
    secret = os.getenv("SUPABASE_SECRET_KEY", "")
    if not supabase_url or not secret:
        return None
    return supabase_url, secret


def _expires_at() -> str:
    retention_days = int(os.getenv("FILE_RETENTION_DAYS", "7"))
    return (datetime.now(timezone.utc) + timedelta(days=retention_days)).isoformat()


async def _post(path: str, payload: Any, *, query: str = "", prefer: str = "return=minimal") -> bool:
    config = _config()
    if config is None:
        return False
    supabase_url, secret = config
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                f"{supabase_url}{path}{query}",
                headers={
                    "apikey": secret,
                    "Authorization": f"Bearer {secret}",
                    "Content-Type": "application/json",
                    "Prefer": prefer,
                },
                json=payload,
            )
            response.raise_for_status()
            return True
    except Exception:
        return False


async def save_scan_evidence(
    scan_id: str,
    user_id: str,
    threat_intel: dict,
    recon_data: dict,
    browser_data: dict,
) -> bool:
    """Save the per-scan evidence snapshot."""
    return await _post(
        "/rest/v1/scan_evidence",
        {
            "scan_id": scan_id,
            "user_id": user_id,
            "threat_intel": threat_intel,
            "recon_data": recon_data,
            "browser_data": browser_data,
            "expires_at": _expires_at(),
        },
        query="?on_conflict=scan_id",
        prefer="resolution=merge-duplicates,return=minimal",
    )


async def save_evidence_items(scan_id: str, user_id: str, items: list[dict[str, Any]]) -> bool:
    """Persist normalized evidence rows. Returns False when no row could be written."""
    if not items:
        return True
    expires_at = _expires_at()
    rows = [
        {
            "scan_id": scan_id,
            "user_id": user_id,
            "evidence_id": item["evidence_id"],
            "kind": item["kind"],
            "skill": item.get("skill"),
            "observed": bool(item.get("observed", True)),
            "fact": str(item.get("fact") or "")[:500],
            "payload": item.get("payload") or {},
            "expires_at": expires_at,
        }
        for item in items
    ]
    return await _post(
        "/rest/v1/scan_evidence_items",
        rows,
        query="?on_conflict=scan_id,evidence_id",
        prefer="resolution=merge-duplicates,return=minimal",
    )
