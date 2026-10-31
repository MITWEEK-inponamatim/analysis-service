import asyncio
import json

import pytest

from app import tools
from app.tools import ToolContext, build_tools, tool_names

EXPECTED = [
    "check_url_reputation",
    "inspect_website",
    "get_page_metadata",
    "inspect_forms",
    "analyze_application",
    "lookup_phone",
    "analyze_message",
    "extract_image_text",
    "search_verification_evidence",
]


def _by_name(context):
    return {tool.name: tool for tool in build_tools(context)}


def _call(name, arguments, context):
    return json.loads(asyncio.run(_by_name(context)[name].ainvoke(arguments)))


def test_whitelist_matches_the_handoff():
    assert tool_names() == EXPECTED


def test_scan_id_mismatch_is_rejected_and_audited():
    context = ToolContext(scan_id="scan-1", user_id="user-1", kind="url", page={"title": "Example"})
    result = _call("inspect_website", {"scan_id": "scan-2"}, context)
    assert result["available"] is False
    assert context.calls[-1]["allowed"] is False


def test_page_tools_never_fetch_and_only_read_evidence():
    page = {"final_url": "https://login.example/", "title": "Sign in", "forms": [{"action": "https://collect.example/", "method": "POST", "password_fields": 1}], "redirect_chain": [{"url": "https://login.example/"}], "external_domains": ["collect.example"]}
    context = ToolContext(scan_id="scan-1", user_id="user-1", kind="url", page=page)
    metadata = _call("get_page_metadata", {"scan_id": "scan-1"}, context)
    forms = _call("inspect_forms", {"scan_id": "scan-1"}, context)
    summary = _call("inspect_website", {"scan_id": "scan-1"}, context)
    assert metadata["title"] == "Sign in"
    assert forms["forms"][0]["password_fields"] == 1
    assert summary["external_domains"] == ["collect.example"]


@pytest.mark.parametrize("url", ["http://127.0.0.1/admin", "http://localhost/x", "file:///etc/passwd", "http://169.254.169.254/latest", "https://example.test/" + "a" * 3000])
def test_reputation_tool_rejects_unsafe_or_invalid_urls(url):
    context = ToolContext(scan_id="scan-1", user_id="user-1", kind="message")
    result = _call("check_url_reputation", {"url": url}, context)
    assert result["available"] is False
    assert result["reason"] in {"address_not_public", "host_not_public", "scheme_not_allowed", "url_length_invalid"}
    assert context.calls[-1]["allowed"] is False


def test_reputation_tool_marks_missing_providers_as_unavailable():
    context = ToolContext(scan_id="scan-1", user_id="user-1", kind="message")
    result = _call("check_url_reputation", {"url": "https://example.test/login"}, context)
    assert result["checks_unavailable"] == ["safe_browsing", "virustotal"]
    assert result["findings"] == []


def test_file_tools_require_an_allowed_file_id():
    context = ToolContext(scan_id="scan-1", user_id="user-1", kind="application", features={"package_name": "com.example"}, file_ids=["scan-1"])
    denied = _call("analyze_application", {"file_id": "scan-9"}, context)
    allowed = _call("analyze_application", {"file_id": "scan-1"}, context)
    assert denied["available"] is False
    assert allowed["package_name"] == "com.example"


def test_ocr_tool_only_returns_cached_text():
    context = ToolContext(scan_id="scan-1", user_id="user-1", kind="image", ocr_text="Selamat anda menang", file_ids=["scan-1"])
    result = _call("extract_image_text", {"file_id": "scan-1"}, context)
    assert result["text"] == "Selamat anda menang"


def test_lookup_phone_validates_region_and_digits(monkeypatch):
    async def reports(_e164):
        return [{"category": "scam", "status": "verified"}]

    monkeypatch.setattr(tools, "fetch_reports", reports)
    context = ToolContext(scan_id="scan-1", user_id="user-1", kind="message")
    good = _call("lookup_phone", {"number": "+6281234567890", "default_region": "ID"}, context)
    bad_region = _call("lookup_phone", {"number": "+6281234567890", "default_region": "ZZ"}, context)
    bad_number = _call("lookup_phone", {"number": "12", "default_region": "ID"}, context)
    assert good["e164"] == "+6281234567890"
    assert good["reports"]["verified"] == 1
    assert bad_region["available"] is False
    assert bad_number["available"] is False


def test_message_tool_and_exa_tool_degrade_without_keys(monkeypatch):
    monkeypatch.delenv("EXA_API_KEY", raising=False)
    context = ToolContext(scan_id="scan-1", user_id="user-1", kind="message")
    assert _call("analyze_message", {"text": "kirim OTP sekarang"}, context)["terms"] == ["otp"]
    assert _call("search_verification_evidence", {"claims": "Bank X membagikan hadiah"}, context)["reason"] == "exa_unavailable"
