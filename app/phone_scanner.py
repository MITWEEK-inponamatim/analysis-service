"""Phone number scanner: normalisation, community reports, and honest limitations.

A valid number is not proof of identity, and a report is not proof of fraud. The report
therefore keeps risk, confidence, and coverage separate (handoff 6.3 and 7.5).
"""

import os
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from .risk import assess, finding
from .phone_reports import category_label
from .schemas import ScanReport

try:  # optional at runtime; the service must start without the library installed
    import phonenumbers

    PHONENUMBERS_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when the dependency is absent
    phonenumbers = None
    PHONENUMBERS_AVAILABLE = False

DIGITS = re.compile(r"\D+")

REGION_CALLING_CODES = {
    "ID": "62",
}

INDONESIA_COUNTRY_CODE = 62
INDONESIA_REGION = "ID"

LINE_TYPES = {
    "MOBILE": "mobile",
    "FIXED_LINE": "fixed_line",
    "FIXED_LINE_OR_MOBILE": "fixed_line_or_mobile",
    "TOLL_FREE": "toll_free",
    "PREMIUM_RATE": "premium_rate",
    "SHARED_COST": "shared_cost",
    "VOIP": "voip",
    "PERSONAL_NUMBER": "personal_number",
    "PAGER": "pager",
    "UAN": "uan",
    "VOICEMAIL": "voicemail",
    "UNKNOWN": "unknown",
}

PHONE_LIMITATIONS = [
    "Nomor telepon bisa dipalsukan (caller ID spoofing) sehingga nomor asal panggilan atau pesan tidak dapat dipercaya begitu saja.",
    "Nomor bisa berpindah pemilik atau dipakai ulang, jadi reputasi masa lalu tidak selalu mencerminkan pemilik sekarang.",
    "Laporan komunitas bisa keliru, tidak lengkap, atau sengaja memfitnah; laporan tidak membuktikan tindak pidana.",
]


@dataclass
class PhoneNumber:
    input: str
    e164: str = ""
    valid: bool = False
    possible: bool = False
    domestic: bool = False
    region: str = ""
    national: str = ""
    line_type: str = "unknown"
    carrier: str = ""
    parsed_by: str = "fallback"
    reasons: list[str] = field(default_factory=list)


def canonical_digits(number: str) -> str:
    """Digits this number should be stored and searched by.

    0812…, 62812… and +62 0812… are one and the same subscriber. The third form still carries
    the trunk 0 after the country code, and storing it would split one number across two keys —
    so a report made under one spelling would be invisible to a search using another. Indonesian
    subscriber numbers never start with 0 once the +62 is there, which makes that 0 safe to drop.
    """
    digits = DIGITS.sub("", (number or "").strip())
    if digits.startswith("62"):
        subscriber = digits[2:]
        return "62" + (subscriber[1:] if subscriber.startswith("0") else subscriber)
    return digits


def normalize_number(number: str, default_region: str = "ID") -> PhoneNumber:
    # Scope is Indonesian numbers, so the caller-supplied region never decides how the number is
    # parsed. Foreign numbers are caught by the +62 country-code check below, not by trusting
    # this field — otherwise region="SG" would quietly make +65 numbers look normal.
    region = INDONESIA_REGION
    digits = canonical_digits(number)
    parse_target = f"+{digits}" if digits.startswith("62") else (number or "").strip()
    result = PhoneNumber(input=number, region=region)
    if not PHONENUMBERS_AVAILABLE:
        return _fallback_normalize(result, region)

    result.parsed_by = "phonenumbers"
    try:
        parsed = phonenumbers.parse(parse_target, region)
    except Exception:
        result.reasons.append("unparseable")
        return _fallback_normalize(result, region)

    result.possible = bool(phonenumbers.is_possible_number(parsed))
    result.valid = bool(phonenumbers.is_valid_number(parsed))
    result.e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    result.national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    result.domestic = getattr(parsed, "country_code", None) == INDONESIA_COUNTRY_CODE
    result.region = phonenumbers.region_code_for_number(parsed) or region
    result.line_type = _line_type(parsed)
    try:
        result.carrier = phonenumbers.carrier.name_for_number(parsed, "en") or ""
    except Exception:
        result.carrier = ""
    if not result.valid:
        result.reasons.append("invalid_for_region")
    if not result.domestic:
        result.reasons.append("not_indonesia")
    if result.line_type == "premium_rate":
        result.reasons.append("premium_rate")
    return result


def _line_type(parsed) -> str:
    """``phonenumbers.number_type`` returns a plain int, so map the value back to a name."""
    types = getattr(phonenumbers, "PhoneNumberType", None)
    if types is None:
        return "unknown"
    value = phonenumbers.number_type(parsed)
    for name, candidate in vars(types).items():
        if not name.startswith("_") and candidate == value:
            return LINE_TYPES.get(name, "unknown")
    return "unknown"


def _fallback_normalize(result: PhoneNumber, region: str) -> PhoneNumber:
    """Deterministic E.164-ish normalisation used when ``phonenumbers`` is unavailable."""
    digits = canonical_digits(result.input)
    if not digits:
        result.reasons.append("unparseable")
        return result
    result.parsed_by = "fallback"
    calling_code = REGION_CALLING_CODES.get(region, "")
    if calling_code and digits.startswith(calling_code):
        e164_digits = digits
    elif (result.input or "").strip().startswith("+"):
        e164_digits = digits
    elif digits.startswith("0"):
        e164_digits = calling_code + digits[1:]
    else:
        e164_digits = calling_code + digits
    result.e164 = f"+{e164_digits}"
    result.national = digits
    result.domestic = e164_digits.startswith("62")
    result.possible = 8 <= len(e164_digits) <= 15
    result.valid = result.possible
    if not result.valid:
        result.reasons.append("invalid_length")
    if not result.domestic:
        result.reasons.append("not_indonesia")
    return result


def normalize_payload(number: str, default_region: str = "ID") -> dict[str, Any]:
    """Single normalisation contract shared by the scanner and the Go API.

    The Go API calls this before storing a community report so every stored number is the
    same E.164 string the scanner would compute (no second, drifting implementation).
    """
    parsed = normalize_number(number, default_region)
    return {
        "input": parsed.input,
        "e164": parsed.e164,
        "valid": parsed.valid,
        "domestic": parsed.domestic,
        "possible": parsed.possible,
        "region": parsed.region,
        "line_type": parsed.line_type,
        "carrier": parsed.carrier,
        "parsed_by": parsed.parsed_by,
        "reasons": parsed.reasons,
    }


def _supabase_config() -> tuple[str, str] | None:
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    secret = os.getenv("SUPABASE_SECRET_KEY", "")
    if not url or not secret:
        return None
    return url, secret


REPORT_COLUMNS = "id,category,source,status,created_at,reported_by,evidence_url"
# The evidence column only exists after the 2026-11-04 migration, which is applied by hand in the
# hosted SQL Editor. PostgREST rejects a whole select for one unknown column, and that would read
# as "community reports unavailable" and hide every report — so the read retries without it.
REPORT_COLUMNS_WITHOUT_EVIDENCE = "id,category,source,status,created_at,reported_by"


async def fetch_reports(e164: str, limit: int = 20) -> list[dict[str, Any]] | None:
    """Return community reports for a number, or None when the data source is unavailable."""
    config = _supabase_config()
    if not config or not e164:
        return None
    url, secret = config
    for attempt, columns in enumerate((REPORT_COLUMNS, REPORT_COLUMNS_WITHOUT_EVIDENCE)):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{url}/rest/v1/phone_reports",
                    params={"number_e164": f"eq.{e164}", "select": columns, "order": "created_at.desc", "limit": str(limit)},
                    headers={"apikey": secret, "Authorization": f"Bearer {secret}"},
                )
                if response.status_code != 200 and attempt == 0:
                    continue
                response.raise_for_status()
                rows = response.json()
        except Exception:
            continue
        return rows if isinstance(rows, list) else None
    return None


def _age_days(value: Any):
    from datetime import datetime, timezone

    text = str(value or "").strip()
    if not text:
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - moment).total_seconds() // 86400))


def summarize_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Explainable trust summary: distinct reporters, verification, recency, categories."""
    verified = [row for row in reports if str(row.get("status", "")).lower() in {"verified", "confirmed"}]
    pending = [row for row in reports if str(row.get("status", "")).lower() not in {"verified", "confirmed", "rejected", "rejected_spam"}]
    # Rejected rows are removed by moderation, so they must not lend weight to the sentence the
    # user reads: "3 pelapor berbeda" would count accounts whose report was deleted as spam.
    kept = [row for row in reports if str(row.get("status", "")).lower() not in {"rejected", "rejected_spam"}]
    reporters = {str(row.get("reported_by")) for row in kept if row.get("reported_by")}
    categories = sorted({category_label(row.get("category")) for row in kept})
    ages = [age for age in (_age_days(row.get("created_at")) for row in kept) if age is not None]
    return {
        "reports": len(reports),
        "verified": len(verified),
        "pending": len(pending),
        "distinct_reporters": len(reporters),
        "categories": categories,
        "last_report_days": min(ages) if ages else None,
    }


def review_cards(reports: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    """Community reviews shaped for display: never echoes ``reported_by``.

    Rejected rows are moderation outcomes, not opinions, so they stay out of the list.
    """
    cards: list[dict[str, Any]] = []
    for row in reports:
        status = str(row.get("status", "")).lower()
        if status not in {"pending", "verified"}:
            continue
        cards.append({
            "id": str(row.get("id") or ""),
            "category": category_label(row.get("category")),
            "status": status,
            "age_days": _age_days(row.get("created_at")),
            "evidence_url": str(row.get("evidence_url") or "") or None,
        })
    return cards[:limit]


def _report_finding(e164: str, reports: list[dict[str, Any]]):
    summary = summarize_reports(reports)
    verified = summary["verified"]
    pending = summary["pending"]
    reporters = summary["distinct_reporters"]
    categories = summary["categories"]
    if not verified and not pending:
        return None
    recency = "" if summary["last_report_days"] is None else f" Laporan terakhir {summary['last_report_days']} hari lalu."
    metadata = {"number_e164": e164, **summary}
    # Severity follows independent corroboration, never volume: repeated claims from a single
    # reporter (or a single account) must not reach "high".
    if verified >= 2 and reporters >= 2:
        return finding(
            f"Nomor dilaporkan sebagai {', '.join(categories) or 'mencurigakan'} oleh {verified} laporan terverifikasi dari {reporters} pelapor berbeda.{recency}",
            "phone_reports", "high", metadata, confidence="medium",
        )
    if verified >= 1:
        return finding(
            f"Nomor telah dilaporkan sebagai {', '.join(categories) or 'mencurigakan'} ({verified} laporan terverifikasi, {reporters} pelapor berbeda).{recency}",
            "phone_reports", "medium", metadata, confidence="medium",
        )
    severity = "medium" if (pending >= 3 and reporters >= 2) else "low"
    return finding(
        f"Ada {pending} laporan komunitas yang belum terverifikasi untuk nomor ini ({reporters} pelapor berbeda).{recency}",
        "phone_reports", severity, metadata, confidence="low",
    )


async def scan_phone(scan_id: str, number: str, default_region: str = "ID") -> ScanReport:
    """Run the phone graph: normalisation -> community reports -> deterministic assessment."""
    from .graph.phone import build_phone_graph
    from .graph.runner import run_graph

    state = {"scan_id": scan_id, "number": number, "default_region": default_region}
    result = await run_graph(build_phone_graph, state, scan_id)
    return result["report"]
