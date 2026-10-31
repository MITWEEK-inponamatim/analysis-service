import asyncio

import pytest

pytest.importorskip("langgraph")

from app.risk import assess
from app.url_graph import build_url_graph


def _report(scan_id, findings=None, artifacts=None, checks=None, unavailable=None):
    report = assess(scan_id, "url", findings or [], checks or ["url_syntax"], unavailable or [])
    report.artifacts.update(artifacts or {})
    return report


def test_url_graph_validates_before_analysis(monkeypatch):
    seen = []

    async def allow(_url):
        seen.append("validated")
        return True

    monkeypatch.setattr("app.browser_guard.validate_target", allow)
    seen_report = _report("scan")

    async def analyze(scan_id, url, user_id, *_args, **_kwargs):
        seen.append("analyzed")
        return _report(scan_id, artifacts={"final_url": url})

    monkeypatch.setattr("app.scanners.scan_url_pipeline", analyze)
    graph = build_url_graph()
    result = asyncio.run(graph.ainvoke({"scan_id": "scan", "user_id": "user", "url": "https://example.com"}))

    assert result["report"].scan_id == "scan"
    assert seen == ["validated", "analyzed"]
    assert result["iterations"] == 1


def test_url_graph_routes_private_url_to_blocked_report(monkeypatch):
    seen = []

    async def reject(_url):
        raise ValueError("private network")

    async def analyze(_scan_id, _url, _user_id, *_args, validation_result=None, **_kwargs):
        seen.append(validation_result)
        return _report("scan", unavailable=["public_dns_validation"])

    monkeypatch.setattr("app.browser_guard.validate_target", reject)
    monkeypatch.setattr("app.scanners.scan_url_pipeline", analyze)
    graph = build_url_graph()
    result = asyncio.run(graph.ainvoke({"scan_id": "scan", "user_id": "user", "url": "http://127.0.0.1"}))

    assert seen == [False]
    assert "public_dns_validation" in result["report"].risk["coverage"]["checks_unavailable"]


def test_redirect_to_other_host_triggers_one_bounded_followup(monkeypatch):
    calls = []

    async def allow(_url):
        return True

    async def analyze(scan_id, url, user_id, *_args, validation_result=None, inspect_browser=True, **_kwargs):
        calls.append((url, inspect_browser))
        if inspect_browser:
            return _report(scan_id, artifacts={"final_url": "https://landing.example/login", "redirect_chain": [{"url": "https://landing.example/login", "status": 200}]})
        return _report("scan", checks=["url_syntax", "safe_browsing"])

    monkeypatch.setattr("app.browser_guard.validate_target", allow)
    monkeypatch.setattr("app.scanners.scan_url_pipeline", analyze)
    graph = build_url_graph()
    result = asyncio.run(graph.ainvoke({"scan_id": "scan", "user_id": "user", "url": "https://bit.ly/abc", "iterations": 1}))

    assert calls == [("https://bit.ly/abc", True), ("https://landing.example/login", False)]
    assert result["iterations"] == 2
    assert any("Pemeriksaan tambahan" in text for text in result["report"].limitations)


def test_same_host_redirect_does_not_loop(monkeypatch):
    calls = []

    async def allow(_url):
        return True

    async def analyze(scan_id, url, user_id, *_args, **_kwargs):
        calls.append((url, True))
        return _report(scan_id, artifacts={"final_url": "https://example.com/dashboard"})

    monkeypatch.setattr("app.browser_guard.validate_target", allow)
    monkeypatch.setattr("app.scanners.scan_url_pipeline", analyze)
    graph = build_url_graph()
    result = asyncio.run(graph.ainvoke({"scan_id": "scan", "user_id": "user", "url": "https://example.com/login", "iterations": 1}))

    assert calls == [("https://example.com/login", True)]
    assert result["iterations"] == 1


def test_cross_domain_form_action_triggers_reputation_deep_check(monkeypatch):
    calls = []

    async def allow(_url):
        return True

    async def analyze(scan_id, url, user_id, *_args, validation_result=None, inspect_browser=True, **_kwargs):
        calls.append((url, inspect_browser))
        if inspect_browser:
            return _report(scan_id, artifacts={
                "final_url": url,
                "form_actions": ["https://collect.example/login", "https://collect.example/login", "https://other.example/post"],
            })
        from app.risk import finding

        return _report(scan_id, findings=[finding("domain pelapor ancaman", "virustotal", "high")], checks=["url_syntax", "virustotal"])

    monkeypatch.setattr("app.browser_guard.validate_target", allow)
    monkeypatch.setattr("app.scanners.scan_url_pipeline", analyze)
    graph = build_url_graph()
    result = asyncio.run(graph.ainvoke({"scan_id": "scan", "user_id": "user", "url": "https://bank.example/login", "iterations": 1}))

    assert calls == [
        ("https://bank.example/login", True),
        ("https://collect.example/login", False),
        ("https://other.example/post", False),
    ]
    assert result["iterations"] == 2
    assert any(item.indicator.startswith("Tujuan formulir") for item in result["report"].findings)
    assert result["report"].outcome == "confirmed_threat"
    assert any("Pemeriksaan tambahan" in text for text in result["report"].limitations)
