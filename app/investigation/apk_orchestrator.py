"""APK investigation orchestrator: hybrid dual-agent, no planner.

Flow: seed evidence → [behavior || obfuscation] → merge → result

Bounded: single pass, MAX_SKILL_CALLS=6 per agent, 45s timeout each.
"""

import asyncio
import re
from typing import Any

from ..risk import finding
from ..schemas import Finding
from .apk_agents import run_behavior_agent, run_obfuscation_agent
from .apk_executor import APKExecutor
from .envelopes import SkillEnvelope
from .evidence import EvidenceStore


class InvestigationResult:
    """Result from APK investigation."""
    
    def __init__(
        self,
        findings: list[Finding] | None = None,
        unavailable: list[str] | None = None,
        artifacts: dict[str, Any] | None = None,
        usage: dict[str, Any] | None = None,
    ):
        self.findings = findings or []
        self.unavailable = unavailable or []
        self.artifacts = artifacts or {}
        self.usage = usage or {}


async def run_apk_investigation(
    scan_id: str,
    user_id: str,
    features: dict[str, Any],
    decompiled: dict[str, Any],
    deterministic_findings: list[Any],
    gate_reasons: list[str],
    unavailable: list[str],
) -> InvestigationResult:
    """
    Run hybrid dual-agent investigation on APK.
    
    Architecture:
    1. Seed evidence store with deterministic findings + decompiled metadata
    2. Run behavior + obfuscation agents in parallel (asyncio.gather)
    3. Merge findings (dedupe, sort by severity)
    4. Return result
    
    No planner, no reanalyze loop — single pass, agents self-direct.
    """
    
    # Seed evidence store
    store = EvidenceStore(scan_id, user_id)
    
    for item in deterministic_findings:
        if isinstance(item, dict):
            payload = {
                "indicator": item.get("indicator", ""),
                "severity": item.get("severity", ""),
                "source": item.get("source", ""),
                "metadata": item.get("metadata", {}),
            }
        else:
            payload = {
                "indicator": getattr(item, "indicator", ""),
                "severity": getattr(item, "severity", ""),
                "source": getattr(item, "source", ""),
                "metadata": getattr(item, "metadata", {}),
            }
        store.add("finding", payload, skill="deterministic", fact="static_analysis_finding")
    
    # Add manifest
    manifest = features.get("manifest", {})
    store.add(
        "manifest",
        {
            "package": manifest.get("package", "unknown"),
            "permissions": manifest.get("permissions", []),
            "app_label": manifest.get("app_label", ""),
        },
        skill="androguard",
        fact="manifest_parsed",
    )
    
    # Add decompiled metadata
    store.add(
        "decompilation",
        {
            "package": decompiled.get("package_name", "unknown"),
            "classes": decompiled.get("classes", [])[:50],
            "native_libs": decompiled.get("native_libs", {}),
            "code_patterns": list(decompiled.get("code_patterns", {}).keys()),
            "obfuscation_detected": decompiled.get("obfuscation_detected", False),
        },
        skill="jadx",
        fact="decompilation_complete",
    )
    
    # Initialize executor
    executor = APKExecutor(
        store=store,
        scan_id=scan_id,
        features=features,
        decompiled_index=decompiled.get("code_index", {}),
        code_patterns=decompiled.get("code_patterns", {}),
    )
    
    # Run agents in parallel
    try:
        behavior_task = run_behavior_agent(executor, store, features, decompiled, deterministic_findings)
        obfuscation_task = run_obfuscation_agent(executor, store, features, decompiled, deterministic_findings)
        
        behavior_result, obfuscation_result = await asyncio.gather(
            behavior_task,
            obfuscation_task,
            return_exceptions=False,
        )
    
    except Exception as e:
        return InvestigationResult(
            unavailable=[f"agent_execution_failed: {str(e)[:100]}"],
            artifacts={
                "investigation": {
                    "status": "failed",
                    "gate_reasons": gate_reasons,
                    "error": str(e)[:200],
                }
            },
        )
    
    findings = _merge_findings(behavior_result, obfuscation_result)
    evidence_ids = sorted(item["evidence_id"] for item in store.items())
    usage_records = [
        {
            "model": envelope.model,
            "prompt_tokens": envelope.prompt_tokens,
            "completion_tokens": envelope.completion_tokens,
            "latency_ms": envelope.latency_ms,
            "status": envelope.status,
        }
        for envelope in (behavior_result, obfuscation_result)
        if envelope.model
    ]
    artifacts = {
        "investigation": {
            "status": "completed" if not behavior_result.unavailable and not obfuscation_result.unavailable else "partial",
            "gate_reasons": gate_reasons,
            "behavior": {"summary": behavior_result.meta.get("summary", ""), "findings": [item.model_dump() for item in behavior_result.findings]},
            "obfuscation": {"summary": obfuscation_result.meta.get("summary", ""), "level": obfuscation_result.meta.get("obfuscation_level", "unknown"), "findings": [item.model_dump() for item in obfuscation_result.findings]},
            "behavior_tool_calls": behavior_result.tool_calls,
            "obfuscation_tool_calls": obfuscation_result.tool_calls,
            "evidence_count": len(store.items()),
            "evidence_ids": evidence_ids[:50],
        }
    }

    from ..evidence_storage import save_evidence_items, save_llm_usage

    persisted = await save_evidence_items(scan_id, user_id, store.items())
    if not persisted:
        unavailable.append("evidence_items_storage")
        artifacts["investigation"]["evidence_storage"] = "failed"
    if usage_records and not await save_llm_usage(scan_id, usage_records):
        unavailable.append("llm_usage_storage")
        artifacts["investigation"]["usage_storage"] = "failed"

    schema_findings = [
        finding(
            item.indicator,
            "agent_investigation",
            item.severity,
            {
                "evidence_ids": item.evidence_ids,
                "confidence": item.confidence,
                "interpretation": item.interpretation,
                "class_name": item.class_name,
                "method_name": item.method_name,
                "extracted_data": item.extracted_data,
            },
            item.confidence,
        )
        for item in findings
    ]

    return InvestigationResult(
        findings=schema_findings,
        unavailable=unavailable,
        artifacts=artifacts,
        usage={
            "prompt_tokens": behavior_result.prompt_tokens + obfuscation_result.prompt_tokens,
            "completion_tokens": behavior_result.completion_tokens + obfuscation_result.completion_tokens,
            "tokens": behavior_result.tokens + obfuscation_result.tokens,
            "latency_ms": behavior_result.latency_ms + obfuscation_result.latency_ms,
            "records": usage_records,
        },
    )


def _merge_findings(
    behavior: SkillEnvelope,
    obfuscation: SkillEnvelope,
) -> list[Any]:
    """Merge and deduplicate findings from both agents."""
    
    all_findings = []
    all_findings.extend(behavior.findings or [])
    all_findings.extend(obfuscation.findings or [])
    
    # Dedupe by indicator (case-insensitive)
    seen = set()
    unique = []
    for f in all_findings:
        key = re.sub(r"\s+", " ", f.indicator.casefold()).strip()
        if key not in seen:
            seen.add(key)
            unique.append(f)
    
    # Sort by severity
    priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    unique.sort(key=lambda f: priority.get(f.severity, 5))
    
    return unique
