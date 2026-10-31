import asyncio

import pytest

from app import scanners


def test_url_scan_uses_browser_evidence_and_reports_password_exfiltration(monkeypatch):
    async def evidence(_url, _scan_id, _user_id):
        return {
            "final_url": "https://login.example/",
            "title": "Example",
            "visible_text": "Sign in",
            "forms": [{"method": "POST", "action": "https://collect.example/login", "password_fields": 1}],
            "external_domains": ["collect.example"],
            "redirect_chain": [{"url": "https://login.example/", "status": 200}],
            "network_requests": [],
            "screenshot_path": "user/scan/page.png",
        }

    monkeypatch.setattr("app.browser_guard.resolve_public", lambda *_args: ["8.8.8.8"])
    monkeypatch.setattr("app.browser_client.inspect_website", evidence)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    report = asyncio.run(scanners.scan_url_pipeline("scan", "https://login.example/", "user"))

    assert report.outcome == "suspicious"
    assert report.risk["level"] == "high"
    assert any("mengirimkan kredensial" in item.indicator for item in report.findings)
    assert report.artifacts["screenshot_path"] == "user/scan/page.png"
    assert "browser_inspection" in report.risk["coverage"]["checks_run"]


def test_browser_ssrf_attempt_is_reported_as_high_risk(monkeypatch):
    async def evidence(*_args):
        return {"final_url": "https://example.com/", "forms": [], "external_domains": [], "network_requests": [], "redirect_chain": [], "failed_requests": ["http://metadata.internal/"], "blocked_requests": [], "ssrf_blocked": True}

    monkeypatch.setattr("app.browser_guard.resolve_public", lambda *_args: ["8.8.8.8"])
    monkeypatch.setattr("app.browser_client.inspect_website", evidence)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    report = asyncio.run(scanners.scan_url_pipeline("scan", "https://example.com/", "user"))
    assert report.risk["level"] == "high"
    assert any(item.source == "ssrf_guard" for item in report.findings)


def test_private_url_stops_before_browser(monkeypatch):
    async def inspect(*_args):
        raise AssertionError("browser inspection must not run")

    monkeypatch.setattr("app.browser_guard.resolve_public", lambda *_args: (_ for _ in ()).throw(ValueError("private")))
    monkeypatch.setattr("app.browser_client.inspect_website", inspect)
    report = asyncio.run(scanners.scan_url_pipeline("scan", "http://127.0.0.1/", "user"))
    assert "browser_inspection" in report.risk["coverage"]["checks_unavailable"]


def test_reputation_only_pass_skips_browser(monkeypatch):
    async def inspect(*_args):
        raise AssertionError("browser inspection must not run for a reputation-only pass")

    monkeypatch.setattr("app.browser_guard.resolve_public", lambda *_args: ["8.8.8.8"])
    monkeypatch.setattr("app.browser_client.inspect_website", inspect)
    report = asyncio.run(scanners.scan_url_pipeline("scan", "https://example.com/", "user", inspect_browser=False))
    assert "browser_inspection" not in report.risk["coverage"]["checks_run"]
    assert "browser_inspection" not in report.risk["coverage"]["checks_unavailable"]


@pytest.mark.parametrize("provider", ["safe_browsing", "virustotal"])
def test_reputation_flags_are_reported(monkeypatch, provider):
    async def flagged(_url):
        from app.risk import finding

        return [finding("flagged by provider", provider, "high")]

    other = "virustotal" if provider == "safe_browsing" else "safe_browsing"

    async def clean(_url):
        return []

    monkeypatch.setattr("app.browser_guard.resolve_public", lambda *_args: ["8.8.8.8"])
    monkeypatch.setattr("app.browser_client.inspect_website", lambda *_args, **_kwargs: _no_browser())
    monkeypatch.setattr(f"app.reputation.{provider}", flagged)
    monkeypatch.setattr(f"app.reputation.{other}", clean)
    report = asyncio.run(scanners.scan_url_pipeline("scan", "https://example.com/", "user"))
    assert report.outcome == "confirmed_threat"
    assert provider in report.risk["coverage"]["checks_run"]


async def _no_browser():
    return {"final_url": "https://example.com/", "forms": [], "external_domains": [], "network_requests": [], "redirect_chain": []}
