"""Whitelisted tools the LLM may call (handoff 7.3).

Every tool receives an identifier (``scan_id`` / ``file_id``), never a path or an arbitrary
deterministic pipeline already collected, so the model cannot expand its own reach.
"""

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from . import exa, ic4, malwarebytes, reputation
from .heuristics import MAX_MESSAGE_CHARS, message_terms
from .phone_scanner import fetch_reports, normalize_number

MAX_TOOL_RESULT_CHARS = 6000
ALLOWED_PHONE_REGIONS = {"ID", "MY", "SG", "US", "GB"}
DIGITS_ONLY = re.compile(r"\D+")


@dataclass
class ToolContext:
    """Evidence already collected for one scan; tools only read from here."""

    scan_id: str
    user_id: str
    kind: str
    message: str = ""
    ocr_text: str = ""
    page: dict[str, Any] | None = None
    features: dict[str, Any] | None = None
    phone: dict[str, Any] | None = None
    file_ids: list[str] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    url_checks: dict[str, dict[str, Any]] = field(default_factory=dict)

    def record(self, name: str, arguments: dict[str, Any], allowed: bool, reason: str = "") -> None:
        self.calls.append({"tool": name, "arguments": arguments, "allowed": allowed, "reason": reason})


class CheckUrlReputationArgs(BaseModel):
    url: str = Field(description="Absolute http(s) URL to check against threat-intelligence sources.")


class ScanIdArgs(BaseModel):
    scan_id: str = Field(description="The scan_id supplied in the conversation. Any other value is rejected.")


class FileIdArgs(BaseModel):
    file_id: str = Field(description="The file_id or scan_id supplied in the conversation.")


class LookupPhoneArgs(BaseModel):
    number: str = Field(description="Phone number as written by the user, e.g. +6281234567890.")
    default_region: str = Field(default="ID", description="ISO region used when the number has no country code.")


class AnalyzeMessageArgs(BaseModel):
    text: str = Field(description="Message text to check for social-engineering indicators.")


class SearchEvidenceArgs(BaseModel):
    claims: str = Field(description="Up to 500 characters of factual claims to search for on the public web.")


def _dump(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False)[:MAX_TOOL_RESULT_CHARS]


def _is_public_url(value: str) -> tuple[bool, str]:
    if not value or len(value) > 2048:
        return False, "url_length_invalid"
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        return False, "scheme_not_allowed"
    host = (parts.hostname or "").casefold().rstrip(".")
    if not host:
        return False, "host_missing"
    if host in ("localhost",) or host.endswith((".local", ".internal")):
        return False, "host_not_public"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True, ""
    if not ipaddress.ip_address(address).is_global:
        return False, "address_not_public"
    return True, ""


def _page_or_error(context: ToolContext, scan_id: str) -> dict[str, Any] | None:
    if scan_id != context.scan_id:
        context.record("page_tool", {"scan_id": scan_id}, False, "scan_id_mismatch")
        return None
    return context.page


def build_tools(context: ToolContext) -> list[StructuredTool]:
    async def check_url_reputation(url: str) -> str:
        allowed, reason = _is_public_url(url)
        context.record("check_url_reputation", {"url": url[:200]}, allowed, reason)
        if not allowed:
            return _dump({"available": False, "reason": reason})
        cached = context.url_checks.get(url)
        if cached is None:
            findings: list[dict[str, Any]] = []
            checks: list[str] = []
            unavailable: list[str] = []
            for name, operation in (("ic4", ic4.ic4_lookup), ("malwarebytes", malwarebytes.malwarebytes_lookup), ("safe_browsing", reputation.safe_browsing), ("virustotal", reputation.virustotal)):
                result = await operation(url)
                if result is None:
                    unavailable.append(name)
                else:
                    checks.append(name)
                    findings.extend({"indicator": item.indicator, "severity": item.severity, "source": item.source} for item in result)
            cached = {"available": bool(checks), "checks_run": checks, "checks_unavailable": unavailable, "findings": findings}
        return _dump(cached)

    async def inspect_website(scan_id: str) -> str:
        page = _page_or_error(context, scan_id)
        if page is None:
            return _dump({"available": False, "reason": "no_browser_evidence_for_this_scan"})
        return _dump({
            "available": True,
            "final_url": str(page.get("final_url") or "")[:500],
            "title": str(page.get("title") or "")[:300],
            "redirect_chain": (page.get("redirect_chain") or [])[:10],
            "external_domains": (page.get("external_domains") or [])[:20],
            "visible_text": str(page.get("visible_text") or "")[:1500],
            "ssrf_blocked": bool(page.get("ssrf_blocked")),
        })

    async def get_page_metadata(scan_id: str) -> str:
        page = _page_or_error(context, scan_id)
        if page is None:
            return _dump({"available": False, "reason": "no_browser_evidence_for_this_scan"})
        return _dump({
            "available": True,
            "final_url": str(page.get("final_url") or "")[:500],
            "title": str(page.get("title") or "")[:300],
            "redirect_chain": (page.get("redirect_chain") or [])[:10],
            "request_count": len(page.get("network_requests") or []),
        })

    async def inspect_forms(scan_id: str) -> str:
        page = _page_or_error(context, scan_id)
        if page is None:
            return _dump({"available": False, "reason": "no_browser_evidence_for_this_scan"})
        forms = []
        for form in (page.get("forms") or [])[:20]:
            forms.append({
                "action": str(form.get("action") or "")[:300],
                "method": str(form.get("method") or ""),
                "password_fields": int(form.get("password_fields") or 0),
            })
        return _dump({"available": True, "forms": forms})

    async def analyze_application(file_id: str) -> str:
        allowed = file_id in context.file_ids or file_id == context.scan_id
        context.record("analyze_application", {"file_id": file_id[:120]}, allowed, "" if allowed else "file_id_not_allowed")
        if not allowed:
            return _dump({"available": False, "reason": "file_id_not_allowed"})
        if not context.features:
            return _dump({"available": False, "reason": "static_analysis_unavailable"})
        features = context.features
        return _dump({
            "available": True,
            "package_name": features.get("package_name"),
            "app_label": features.get("app_label"),
            "permissions": (features.get("permissions") or [])[:40],
            "sensitive_permissions": features.get("sensitive_permissions") or [],
            "manifest_indicators": features.get("manifest_indicators") or [],
            "hidden_launcher_icon": bool(features.get("hidden_launcher_icon")),
            "telegram_bot_token": bool(features.get("telegram_bot_token")),
            "hardcoded_urls": (features.get("hardcoded_urls") or [])[:20],
            "packer_hints": features.get("packer_hints") or [],
            "dynamic_code_loading": bool(features.get("dynamic_code_loading")),
        })

    async def lookup_phone(number: str, default_region: str = "ID") -> str:
        region = (default_region or "ID").upper()
        digits = DIGITS_ONLY.sub("", number or "")
        allowed = region in ALLOWED_PHONE_REGIONS and 7 <= len(digits) <= 15
        context.record("lookup_phone", {"number": (number or "")[:40], "region": region}, allowed, "" if allowed else "number_invalid")
        if not allowed:
            return _dump({"available": False, "reason": "number_or_region_invalid"})
        parsed = normalize_number(number, region)
        reports = await fetch_reports(parsed.e164) if parsed.e164 else None
        return _dump({
            "available": True,
            "e164": parsed.e164,
            "valid": parsed.valid,
            "region": parsed.region or region,
            "line_type": parsed.line_type,
            "reports": None if reports is None else {
                "count": len(reports),
                "verified": sum(1 for row in reports if str(row.get("status", "")).lower() in {"verified", "confirmed"}),
                "categories": sorted({str(row.get("category", "unknown")) for row in reports})[:10],
            },
        })

    async def analyze_message(text: str) -> str:
        allowed = len(text or "") <= MAX_MESSAGE_CHARS
        context.record("analyze_message", {"characters": len(text or "")}, allowed, "" if allowed else "text_too_long")
        if not allowed:
            return _dump({"available": False, "reason": "text_too_long"})
        return _dump({"available": True, "terms": message_terms(text), "characters": len(text or "")})

    async def extract_image_text(file_id: str) -> str:
        allowed = file_id in context.file_ids or file_id == context.scan_id
        context.record("extract_image_text", {"file_id": file_id[:120]}, allowed, "" if allowed else "file_id_not_allowed")
        if not allowed:
            return _dump({"available": False, "reason": "file_id_not_allowed"})
        if not context.ocr_text:
            return _dump({"available": False, "reason": "ocr_unavailable"})
        return _dump({"available": True, "text": context.ocr_text[:4000]})

    async def search_verification_evidence(claims: str) -> str:
        allowed = 3 <= len((claims or "").strip()) <= 500
        context.record("search_verification_evidence", {"characters": len(claims or "")}, allowed, "" if allowed else "claims_length_invalid")
        if not allowed:
            return _dump({"available": False, "reason": "claims_length_invalid"})
        result = await exa.search(claims)
        if result is None:
            return _dump({"available": False, "reason": "exa_unavailable"})
        return _dump(result)

    return [
        StructuredTool.from_function(coroutine=check_url_reputation, name="check_url_reputation", description="Check one public http(s) URL against Safe Browsing and VirusTotal. Use for links quoted in the input.", args_schema=CheckUrlReputationArgs),
        StructuredTool.from_function(coroutine=inspect_website, name="inspect_website", description="Read the browser evidence already collected for this scan (URL scans only).", args_schema=ScanIdArgs),
        StructuredTool.from_function(coroutine=get_page_metadata, name="get_page_metadata", description="Return page title, final URL, redirect chain, and request count for this scan.", args_schema=ScanIdArgs),
        StructuredTool.from_function(coroutine=inspect_forms, name="inspect_forms", description="Return the HTML forms found on the inspected page, including password fields.", args_schema=ScanIdArgs),
        StructuredTool.from_function(coroutine=analyze_application, name="analyze_application", description="Return the static analysis summary of the APK sample in this scan.", args_schema=FileIdArgs),
        StructuredTool.from_function(coroutine=lookup_phone, name="lookup_phone", description="Normalise a phone number and read community reports about it.", args_schema=LookupPhoneArgs),
        StructuredTool.from_function(coroutine=analyze_message, name="analyze_message", description="Check a message text for deterministic social-engineering indicators.", args_schema=AnalyzeMessageArgs),
        StructuredTool.from_function(coroutine=extract_image_text, name="extract_image_text", description="Return the OCR text already extracted from the screenshot in this scan.", args_schema=FileIdArgs),
        StructuredTool.from_function(coroutine=search_verification_evidence, name="search_verification_evidence", description="Search the public web for factual claims. Results are unverified evidence, not proof.", args_schema=SearchEvidenceArgs),
    ]


def tool_names() -> list[str]:
    return [tool.name for tool in build_tools(ToolContext(scan_id="", user_id="", kind=""))]
