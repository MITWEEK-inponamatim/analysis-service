"""APK investigation orchestrator: hybrid dual-agent, no planner.

Flow: seed evidence → [behavior || obfuscation] → merge → result

Bounded: single pass, MAX_SKILL_CALLS=6 per agent, 45s timeout each.
"""

import asyncio
import re
from typing import Any

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
    
    # Add deterministic findings
    for finding in deterministic_findings:
        store.add(
            "finding",
            {
                "indicator": getattr(finding, "indicator", finding.get("indicator", "")),
                "severity": getattr(finding, "severity", finding.get("severity", "")),
                "source": getattr(finding, "source", finding.get("source", "")),
                "metadata": getattr(finding, "metadata", finding.get("metadata", {})),
            },
            skill="deterministic",
            fact="static_analysis_finding",
        )
    
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
    
    # Merge findings
    findings = _merge_findings(behavior_result, obfuscation_result)
    
    # Collect evidence IDs
    evidence_ids = list(set(
        (behavior_result.evidence_ids or []) + (obfuscation_result.evidence_ids or [])
    ))
    
    # Build artifacts
    artifacts = {
        "investigation": {
            "status": "completed",
            "gate_reasons": gate_reasons,
            "behavior_tool_calls": behavior_result.tool_calls or 0,
            "obfuscation_tool_calls": obfuscation_result.tool_calls or 0,
            "evidence_count": len(evidence_ids),
            "evidence_ids": evidence_ids[:50],
        }
    }
    
    # Persist evidence items
    from ..evidence_storage import save_evidence_items
    
    persisted = await save_evidence_items(scan_id, user_id, store.items())
    if not persisted:
        unavailable.append("evidence_items_storage")
        artifacts["investigation"]["evidence_storage"] = "failed"
    
    # Convert InvestigationFinding to Finding schema
    schema_findings = []
    for inv_finding in findings:
        schema_findings.append(Finding(
            indicator=inv_finding.indicator,
            category="malware_behavior",
            severity=inv_finding.severity,
            metadata={
                "evidence_ids": inv_finding.evidence_ids,
                "source": "agent_investigation",
            },
            source="agent_investigation",
        ))
    
    
    return InvestigationResult(
        findings=schema_findings,
        unavailable=unavailable,
        artifacts=artifacts,
        usage={"tokens": (behavior_result.tokens or 0) + (obfuscation_result.tokens or 0)},
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
