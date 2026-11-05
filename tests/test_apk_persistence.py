import asyncio
import re

from app import evidence_storage
from app.investigation.evidence import EvidenceStore


USER = "22222222-2222-2222-2222-222222222222"
SCAN = "11111111-1111-1111-1111-111111111111"

def test_evidence_store_redacts_secret_values_recursively():
    store = EvidenceStore(SCAN, USER)
    bot_token = "123456789:" + "A" * 35
    evidence_id = store.add(
        "telegram_c2",
        {"bot_indicators": [f"https://api.telegram.org/bot{bot_token}/sendMessage"]},
        fact="telegram endpoint detected",
    )
    persisted = store.items()[0]["payload"]["bot_indicators"][0]
    assert bot_token not in persisted
    assert "[REDACTED_TELEGRAM_BOT_TOKEN]" in persisted
    assert store.exists(evidence_id)


def test_llm_usage_writes_aggregate_records_only(monkeypatch):
    captured = {}

    async def post(path, payload, **kwargs):
        captured.update(path=path, payload=payload, kwargs=kwargs)
        return True

    monkeypatch.setattr(evidence_storage, "_post", post)
    ok = asyncio.run(evidence_storage.save_llm_usage(SCAN, [{
        "model": "gpt-6-luna",
        "prompt_tokens": 12,
        "completion_tokens": 7,
        "latency_ms": 99,
        "status": "completed",
        "prompt": "never persist prompts",
        "output": "never persist output",
    }]))
    assert ok is True
    assert captured["path"] == "/rest/v1/llm_usage"
    assert captured["payload"] == [{
        "scan_id": SCAN,
        "model": "gpt-6-luna",
        "prompt_tokens": 12,
        "completion_tokens": 7,
        "latency_ms": 99,
        "status": "completed",
    }]


def test_empty_usage_write_is_a_noop(monkeypatch):
    async def fail_if_called(*_args, **_kwargs):
        raise AssertionError("empty usage should not make a request")

    monkeypatch.setattr(evidence_storage, "_post", fail_if_called)
    assert asyncio.run(evidence_storage.save_llm_usage(SCAN, [])) is True



def test_apk_investigation_persists_owned_evidence_and_call_usage(monkeypatch):
    from app.investigation import apk_orchestrator
    from app.investigation.envelopes import SkillEnvelope

    persisted = {}

    async def save_evidence(scan_id, user_id, items):
        persisted["evidence"] = (scan_id, user_id, items)
        return True

    async def save_usage(scan_id, records):
        persisted["usage"] = (scan_id, records)
        return True

    async def behavior(*_args):
        return SkillEnvelope(
            skill="behavior-agent", status="completed", model="gpt-6-luna",
            prompt_tokens=13, completion_tokens=5, tokens=18, latency_ms=42,
        )

    async def obfuscation(*_args):
        return SkillEnvelope(
            skill="obfuscation-agent", status="completed", model="gpt-6-luna",
            prompt_tokens=8, completion_tokens=4, tokens=12, latency_ms=37,
        )

    monkeypatch.setattr("app.evidence_storage.save_evidence_items", save_evidence)
    monkeypatch.setattr("app.evidence_storage.save_llm_usage", save_usage)
    monkeypatch.setattr(apk_orchestrator, "run_behavior_agent", behavior)
    monkeypatch.setattr(apk_orchestrator, "run_obfuscation_agent", obfuscation)
    result = asyncio.run(apk_orchestrator.run_apk_investigation(
        scan_id=SCAN,
        user_id=USER,
        features={"manifest": {"package": "com.example.safe", "permissions": []}},
        decompiled={"package_name": "com.example.safe", "classes": ["com.example.Safe"], "code_index": {}},
        deterministic_findings=[],
        gate_reasons=["test_gate"],
        unavailable=[],
    ))
    assert result.usage["prompt_tokens"] == 21
    assert result.usage["completion_tokens"] == 9
    assert result.usage["tokens"] == 30
    assert len(persisted["evidence"][2]) == 2
    assert len(persisted["usage"][1]) == 2
    assert result.artifacts["investigation"]["behavior"]["summary"] == ""