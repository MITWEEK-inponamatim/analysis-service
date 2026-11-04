"""Backend helpers for community phone reports (Fase 4).

Writes happen in the Go API (it owns the user's identity); this module only needs the
moderation path that turns a ``pending`` report into ``verified`` or ``rejected``.

Privacy bounds that must not be widened:
* the stored ``category`` is one of :data:`REPORT_CATEGORIES` only, never free text;
* the optional ``note`` is moderation context, limited to 280 characters, never sent to an
  LLM and never shown to other users;
* a report is never treated as proof of fraud (see ``phone_scanner._report_finding``).
"""

import os
import re
from typing import Any

import httpx

ALLOWED_STATUSES = {"pending", "verified", "rejected", "rejected_spam"}

# Stored value -> Indonesian label used in report text.
# ``phishing`` and ``pharming`` arrive from the community report form on /community/phone, which
# offers the board's five categories; without a label here a verified phishing report would be
# described as ``lainnya`` in the scan result.
REPORT_CATEGORIES = {
    "penipuan": "penipuan",
    "spam": "spam",
    "telemarketing": "telemarketing",
    "penagih_utang": "penagih utang",
    "peniruan_identitas": "peniruan identitas",
    "lainnya": "lainnya",
    "phishing": "phishing",
    "pharming": "pharming",
}

MAX_NOTE_LENGTH = 280
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def category_label(value: Any) -> str:
    """Map a stored category to its display label; unknown values degrade to ``lainnya``."""
    return REPORT_CATEGORIES.get(str(value or "").strip().lower(), "lainnya")


def valid_report_id(value: str) -> bool:
    return bool(UUID.match(value or ""))


def _supabase() -> tuple[str, str] | None:
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    secret = os.getenv("SUPABASE_SECRET_KEY", "")
    if not url or not secret:
        return None
    return url, secret


class ReportsUnavailable(Exception):
    """Supabase is not configured or the update failed."""


def configure(url: str, secret: str) -> None:
    os.environ["SUPABASE_URL"] = url.rstrip("/")
    os.environ["SUPABASE_SECRET_KEY"] = secret


async def set_status(report_id: str, status: str) -> dict[str, Any]:
    """Update one report's moderation status. Raises ReportsUnavailable on failure."""
    if status not in ALLOWED_STATUSES:
        raise ValueError("unsupported_status")
    config = _supabase()
    if config is None:
        raise ReportsUnavailable("supabase_not_configured")
    base, secret = config
    headers = {"apikey": secret, "Authorization": f"Bearer {secret}", "Prefer": "return=representation"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.patch(
                f"{base}/rest/v1/phone_reports",
                params={"id": f"eq.{report_id}", "select": "id,number_e164,status"},
                headers=headers,
                json={"status": status},
            )
            response.raise_for_status()
            rows = response.json()
    except Exception as error:
        raise ReportsUnavailable(type(error).__name__) from error
    if not isinstance(rows, list) or not rows:
        raise ReportsUnavailable("report_not_found")
    return rows[0]
