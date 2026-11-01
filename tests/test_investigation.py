import asyncio
from pathlib import Path

import pytest

from app.investigation import agents as agents_module
from app.investigation import deterministic as det
from app.investigation import skills
from app.investigation.envelopes import SkillEnvelope
from app.investigation.evidence import EvidenceStore
from app.investigation.executor import EvidenceExecutor
from app.investigation.orchestrator import investigation_enabled, run_investigation
from app.investigation.planner import build_plan
from app.risk import finding

SCAN = "11111111-1111-1111-1111-111111111111"
USER = "22222222-2222-2222-2222-222222222222"


def browser_evidence():
    return {
        "final_url": "https://bca-login.test/",
        "title": "BCA Mobile",
        "visible_text": "Masuk ke akun BCA Anda",
        "meta": {"description": "Login"},
        "headings": ["Masuk"],
        "forms": [
            {
                "method": "post",
                "action": "https://collect.other.test/login",
                "password_fields": 1,
                "input_types": ["text", "password"],
                "input_names": ["username", "password"],
                "input_placeholders": ["", ""],
                "has_email": False,
                "has_username": True,
                "has_otp": False,
            }
        ],
        "redirect_chain": [
            {"url": "https://bit.ly/x", "status": 302},
            {"url": "https://bca-login.test/", "status": 200},
        ],
        "network_requests": [
            {"url": "https://collect.other.test/login", "method": "GET", "resource_type": "fetch", "status": 200},
            {"url": "https://cdn.other.test/app.js", "method": "GET", "resource_type": "script", "status": 200},
        ],
        "external_domains": ["collect.other.test", "cdn.other.test"],
        "js_obfuscation": {"detected": True, "patterns": ["eval_usage"]},
        "links": [{"href": "https://bca-login.test/verify", "text": "Verifikasi"}],
        "iframes": [],
        "logo_candidates": [{"alt": "BCA", "src_host": "cdn.other.test"}],
        "shadow_root_count": 0,
    }


def test_skill_loader_allowlist_and_permissions():
    assert len(skills.names()) == 13
    assert "brand-investigation-gateway" in skills.names()
    assert "brand-investigation-gateway" in skills.load_skill("brand-investigation-gateway", "brand")
    with pytest.raises(skills.SkillError):
        skills.load_skill("not-a-skill")
    with pytest.raises(skills.SkillError):
        skills.load_skill("../../etc/passwd")
    with pytest.raises(skills.SkillError):
        skills.load_skill("inspect-form-elements", "brand")


def test_skill_catalog_is_agent_scoped():
    brand = {item["name"] for item in skills.catalog_for("brand")}
    behavior = {item["name"] for item in skills.catalog_for("behavior")}
    assert "inspect-page-content" in brand & behavior
    assert "inspect-form-elements" in behavior
    assert "inspect-form-elements" not in brand


def test_evidence_store_ids_dedupe_and_redact():
    store = EvidenceStore(SCAN, USER)
    first = store.add("form", {"a": 1, "password": "secret", "long": "x" * 5000})
    second = store.add("form", {"a": 1, "password": "secret", "long": "x" * 5000})
    assert first == second
    assert first.startswith("ev_form_")
    payload = store.get(first)["payload"]
    assert "password" not in payload
    assert len(payload["long"]) == 4000
    valid, invalid = store.validate([first, "ev_form_deadbeef0000"])
    assert valid == [first]
    assert invalid == ["ev_form_deadbeef0000"]


def test_domain_helpers():
    assert det.normalize_host("https://WWW.Example.CO.ID:443/a") == "www.example.co.id"
    assert det.registrable_domain("www.example.co.id") == "example.co.id"
    assert det.registrable_domain("login.bca.co.id") == "bca.co.id"
    assert det.is_shortener("bit.ly")
    assert "brand_token_present" in det.lookalike_rules("bca-login.test", "bca")
    assert det.classify_destination("collect.other.test", "bca-login.test") == "third_party_unknown"
    assert det.classify_destination("login.bca.co.id", "bca.co.id") == "same_registrable_domain"


def test_gate_skips_conclusive_and_runs_on_ambiguity():
    evidence = browser_evidence()
    enabled, reasons = det.investigation_gate([], evidence, [], "https://bca-login.test/")
    assert enabled is True
    assert "sensitive_form" in reasons
    conclusive = finding("known phishing", "virustotal", "high")
    enabled, reasons = det.investigation_gate([conclusive], evidence, [], "https://bca-login.test/")
    assert enabled is False
    assert reasons == ["conclusive_deterministic_finding"]


def test_executor_produces_evidence_linked_findings():
    async def run():
        store = EvidenceStore(SCAN, USER)
        executor = EvidenceExecutor(
            store,
            scan_id=SCAN,
            user_id=USER,
            url="https://bca-login.test/",
            browser_evidence=browser_evidence(),
            deterministic_findings=[],
        )
        forms = await executor.run("inspect-form-elements")
        assert forms.evidence_ids
        assert forms.observations[0].payload["forms"][0]["action_host"] == "collect.other.test"
        assert forms.observations[0].payload["forms"][0]["sensitive_categories"] == ["identity", "password"]
        destination = await executor.run("investigate-form-destination")
        assert any(item.severity == "high" for item in destination.findings)
        assert all(item.evidence_ids for item in destination.findings)
        redirects = await executor.run("investigate-redirect-chain")
        assert redirects.observations[0].payload["registrable_domain_changes"] >= 1

    asyncio.run(run())


def test_planner_selects_only_unexecuted_skills():
    store = EvidenceStore(SCAN, USER)
    executor = EvidenceExecutor(
        store,
        scan_id=SCAN,
        user_id=USER,
        url="https://bca-login.test/",
        browser_evidence=browser_evidence(),
        deterministic_findings=[],
    )
    brand = SkillEnvelope(skill="brand-agent", status="completed", evidence_ids=["ev_page_x"])
    behavior = SkillEnvelope(skill="behavior-agent", status="completed", evidence_ids=["ev_form_x"])
    plan = build_plan(store=store, executor=executor, brand=brand, behavior=behavior, round_number=1)
    names = {step.skill for step in plan.plan}
    assert "investigate-form-destination" in names
    assert "investigate-redirect-chain" in names
    assert len(plan.plan) <= 4

    executor.executed.extend(["inspect-page-content", "investigate-form-destination", "investigate-redirect-chain"])
    executor.executed.extend(["inspect-network-activity", "inspect-javascript-behavior", "inspect-embedded-content"])
    executor.executed.extend(["investigate-external-domains", "investigate-brand-impersonation"])
    plan = build_plan(store=store, executor=executor, brand=brand, behavior=behavior, round_number=1)
    assert plan.plan == []
    assert plan.stop_reason == "no_open_gap"


def test_orchestrator_runs_without_llm(monkeypatch):
    monkeypatch.setattr(agents_module, "chat_model", lambda: None)

    async def no_persist(*_args, **_kwargs):
        return False

    monkeypatch.setattr("app.evidence_storage.save_evidence_items", no_persist)

    async def run():
        enabled, reasons = investigation_enabled([], browser_evidence(), [], "https://bca-login.test/")
        assert enabled
        result = await run_investigation(
            scan_id=SCAN,
            user_id=USER,
            url="https://bca-login.test/",
            browser_evidence=browser_evidence(),
            deterministic_findings=[],
            unavailable=[],
            gate_reasons=reasons,
        )
        assert result.findings
        assert result.artifacts["evidence_count"] > 0
        assert result.artifacts["status"] == "completed"
        assert "evidence_items_storage" in result.unavailable

    asyncio.run(run())
