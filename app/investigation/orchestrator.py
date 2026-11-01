"""LangGraph orchestrator for the agentic investigation phase.

Flow: seed evidence -> Brand and Behavior agents in parallel -> planner ->
targeted collection loop -> finding merge. Bounded by rounds and skill calls.
"""
import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from ..risk import finding as risk_finding
from ..schemas import Finding
from . import deterministic as det
from . import planner as planner_module
from .agents import reanalyze_agent, run_skill_agent
from .envelopes import PlanEnvelope, SkillEnvelope
from .evidence import EvidenceStore
from .executor import EvidenceExecutor

MAX_ROUNDS = planner_module.MAX_ROUNDS
EVIDENCE_SUMMARY_LIMIT = 200

class InvestigationState(TypedDict, total=False):
    scan_id: str
    user_id: str
    url: str
    browser_evidence: dict[str, Any]
    deterministic_findings: list[Any]
    unavailable: list[str]
    gate_reasons: list[str]
    store: EvidenceStore
    executor: EvidenceExecutor
    brand: SkillEnvelope
    behavior: SkillEnvelope
    plan: PlanEnvelope
    round: int
    collected: list[SkillEnvelope]
    findings: list[Finding]
    checks: list[str]
    artifacts: dict[str, Any]
    claimed_brands: list[dict[str, Any]]
    official_identity: dict[str, Any]
    identity_comparison: dict[str, Any]
    brand_investigation_step: int

@dataclass
class InvestigationResult:
    findings: list[Finding] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)


def investigation_enabled(
    findings: list[Any],
    browser_evidence: dict[str, Any] | None,
    unavailable: list[str],
    url: str,
) -> tuple[bool, list[str]]:
    return det.investigation_gate(findings, browser_evidence, unavailable, url)


def _seed(state: InvestigationState) -> dict[str, Any]:
    store = EvidenceStore(state["scan_id"], state["user_id"])
    browser = state.get("browser_evidence") or {}
    store.add(
        "scan",
        {
            "url": state["url"][:2048],
            "final_url": str(browser.get("final_url") or "")[:2048],
            "forms": len(browser.get("forms") or []),
            "network_requests": len(browser.get("network_requests") or []),
            "external_domains": len(browser.get("external_domains") or []),
            "obfuscation_detected": bool((browser.get("js_obfuscation") or {}).get("detected")),
        },
        skill="investigation-seed",
        fact="scan_scope",
    )
    for item in state.get("deterministic_findings") or []:
        store.add(
            "finding",
            {
                "indicator": str(getattr(item, "indicator", ""))[:500],
                "severity": str(getattr(item, "severity", "")),
                "source": str(getattr(item, "source", "")),
                "metadata": getattr(item, "metadata", {}) or {},
            },
            skill=str(getattr(item, "source", "") or "deterministic"),
            fact="deterministic_finding",
        )
    executor = EvidenceExecutor(
        store,
        scan_id=state["scan_id"],
        user_id=state["user_id"],
        url=state["url"],
        browser_evidence=browser,
        deterministic_findings=state.get("deterministic_findings") or [],
    )
    return {"store": store, "executor": executor, "round": 1}


async def _brand_identify(state: InvestigationState) -> dict[str, Any]:
    """Step 1: Identify claimed brands."""
    envelope = await state["executor"].run("identify-claimed-brand", {})
    claimed_brands = []
    for obs in envelope.observations:
        if obs.fact == "brand_claims":
            claimed_brands = obs.payload.get("claimed_brands", [])
            break
    return {"brand_investigation_step": 1, "claimed_brands": claimed_brands, "collected": [envelope]}


async def _brand_verify(state: InvestigationState) -> dict[str, Any]:
    """Step 2: Verify official domains via Exa."""
    claimed_brands = state.get("claimed_brands") or []
    if not claimed_brands:
        return {"brand_investigation_step": 2, "official_identity": {}}
    
    primary_brand = claimed_brands[0].get("name", "")
    envelope = await state["executor"].run("verify-official-domain", {"brand_name": primary_brand})
    
    official_identity = {}
    for obs in envelope.observations:
        if obs.fact == "official_domain_verification":
            official_identity = obs.payload
            break
    
    collected = list(state.get("collected") or [])
    collected.append(envelope)
    return {"brand_investigation_step": 2, "official_identity": official_identity, "collected": collected}


async def _brand_compare(state: InvestigationState) -> dict[str, Any]:
    """Step 3: Compare claimed vs official identity."""
    claimed_brands = state.get("claimed_brands") or []
    official_identity = state.get("official_identity") or {}
    
    # Always run comparison, even with empty official_identity (returns "unknown")
    params = {
        "claimed_brand": claimed_brands[0].get("name", "") if claimed_brands else "",
        "official_domains": official_identity.get("official_domains", []),
        "verification_status": official_identity.get("verification_status", "unknown"),
    }
    
    envelope = await state["executor"].run("compare-brand-identity", params)
    
    identity_comparison = {}
    for obs in envelope.observations:
        if obs.fact == "identity_comparison":
            identity_comparison = obs.payload
            break
    
    collected = list(state.get("collected") or [])
    collected.append(envelope)
    return {"brand_investigation_step": 3, "identity_comparison": identity_comparison, "collected": collected}

async def _brand_impersonation(state: InvestigationState) -> dict[str, Any]:
    """Step 4: Synthesize impersonation findings."""
    claimed_brands = state.get("claimed_brands") or []
    official_identity = state.get("official_identity") or {}
    identity_comparison = state.get("identity_comparison") or {}
    
    if not claimed_brands:
        return {"brand": SkillEnvelope(skill="brand-pipeline", status="completed")}
    
    # Gather evidence IDs from prior steps
    collected = state.get("collected") or []
    evidence_ids = {}
    for env in collected[-3:]:  # Last 3 envelopes
        if env.observations:
            obs = env.observations[0]
            if obs.fact == "brand_claims":
                evidence_ids["brand_claims"] = obs.evidence_id
            elif obs.fact == "official_domain_verification":
                evidence_ids["domain_verification"] = obs.evidence_id
            elif obs.fact == "identity_comparison":
                evidence_ids["identity_comparison"] = obs.evidence_id
    
    params = {
        "claimed_brand": claimed_brands[0].get("name", ""),
        "official_domains": official_identity.get("official_domains", []),
        "verification_status": official_identity.get("verification_status", "unknown"),
        "identity_consistency": identity_comparison.get("consistency_status", "unknown"),
        "domain_relation": identity_comparison.get("domain_relation", "unknown"),
        "lookalike_rules": identity_comparison.get("lookalike_rules", []),
        "service_match_status": identity_comparison.get("service_match", {}).get("status", "unknown"),
        "evidence_ids": evidence_ids,
    }
    
    envelope = await state["executor"].run("investigate-brand-impersonation", params)
    
    collected = list(state.get("collected") or [])
    collected.append(envelope)
    return {"brand": envelope, "brand_investigation_step": 4, "collected": collected}


async def _behavior(state: InvestigationState) -> dict[str, Any]:
    envelope = await run_skill_agent(
        "behavior",
        store=state["store"],
        executor=state["executor"],
        deterministic_findings=state.get("deterministic_findings") or [],
    )
    return {"behavior": envelope}


def _plan(state: InvestigationState) -> dict[str, Any]:
    plan = planner_module.build_plan(
        store=state["store"],
        executor=state["executor"],
        brand=state.get("brand") or SkillEnvelope(skill="brand-agent", status="skipped"),
        behavior=state.get("behavior") or SkillEnvelope(skill="behavior-agent", status="skipped"),
        round_number=int(state.get("round", 1)),
    )
    return {"plan": plan}


async def _execute(state: InvestigationState) -> dict[str, Any]:
    plan = state.get("plan") or PlanEnvelope()
    collected: list[SkillEnvelope] = []
    for step in plan.plan:
        collected.append(await state["executor"].run(step.skill, step.params))

    brand_env = await reanalyze_agent(
        "brand",
        store=state["store"],
        executor=state["executor"],
        deterministic_findings=state.get("deterministic_findings") or [],
        prior=[state.get("brand") or SkillEnvelope(skill="brand-agent", status="skipped")],
        collected=[env for step, env in zip(plan.plan, collected) if step.agent == "brand"],
    )
    behavior_env = await reanalyze_agent(
        "behavior",
        store=state["store"],
        executor=state["executor"],
        deterministic_findings=state.get("deterministic_findings") or [],
        prior=[state.get("behavior") or SkillEnvelope(skill="behavior-agent", status="skipped")],
        collected=[env for step, env in zip(plan.plan, collected) if step.agent == "behavior"],
    )
    return {
        "brand": brand_env,
        "behavior": behavior_env,
        "round": int(state.get("round", 1)) + 1,
        "collected": collected,
    }


def _route_after_plan(state: InvestigationState) -> str:
    plan = state.get("plan")
    if plan and plan.plan and int(state.get("round", 1)) < MAX_ROUNDS:
        return "execute"
    return "finalize"


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    result: list[Finding] = []
    for item in findings:
        key = f"{item.source}|{item.indicator.casefold()}"
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


async def _finalize(state: InvestigationState) -> dict[str, Any]:
    store: EvidenceStore = state["store"]
    executor: EvidenceExecutor = state["executor"]
    brand = state.get("brand") or SkillEnvelope(skill="brand-agent", status="skipped")
    behavior = state.get("behavior") or SkillEnvelope(skill="behavior-agent", status="skipped")

    findings: list[Finding] = []
    for envelope, source in ((brand, "brand_agent"), (behavior, "behavior_agent")):
        for item in envelope.findings:
            valid, _invalid = store.validate(item.evidence_ids)
            if not valid:
                continue
            severity = "high" if item.severity == "critical" else item.severity
            findings.append(
                risk_finding(
                    item.indicator,
                    source,
                    severity,
                    {
                        "evidence_ids": valid,
                        "interpretation": item.interpretation,
                        "agent": envelope.skill,
                    },
                    confidence=item.confidence,
                )
            )
    findings = _dedupe(findings)

    from ..evidence_storage import save_evidence_items

    persisted = await save_evidence_items(state["scan_id"], state["user_id"], store.items())
    unavailable = [f"{name}_unavailable" for env in (brand, behavior) for name in env.unavailable]
    if not persisted:
        unavailable.append("evidence_items_storage")

    skills_run = sorted(set(executor.executed))
    evidence_ids = sorted(store.index())
    artifacts = {
        "status": "completed" if findings else "partial",
        "rounds": int(state.get("round", 1)),
        "gate_reasons": state.get("gate_reasons") or [],
        "skills_run": skills_run,
        "evidence_count": len(evidence_ids),
        "evidence_ids": evidence_ids[:EVIDENCE_SUMMARY_LIMIT],
        "items_persisted": persisted,
        "brand": {
            "status": brand.status,
            "findings": len(brand.findings),
            "gaps": brand.gaps[:10],
            "skills_loaded": (brand.meta or {}).get("skills_loaded", [])[:10],
        },
        "behavior": {
            "status": behavior.status,
            "findings": len(behavior.findings),
            "gaps": behavior.gaps[:10],
            "skills_loaded": (behavior.meta or {}).get("skills_loaded", [])[:10],
        },
        "plan": [
            {"step": step.step, "agent": step.agent, "skill": step.skill, "reason": step.reason}
            for step in (state.get("plan").plan if state.get("plan") else [])
        ][:8],
        "gaps": sorted({gap for env in (brand, behavior) for gap in env.gaps})[:20],
    }
    checks = ["evidence_store", "investigation_planner"]
    if brand.status == "completed":
        checks.append("brand_agent")
    if behavior.status == "completed":
        checks.append("behavior_agent")
    return {"findings": findings, "checks": checks, "unavailable": unavailable, "artifacts": artifacts}


@lru_cache(maxsize=1)
def _compiled_graph():
    graph = StateGraph(InvestigationState)
    graph.add_node("seed", _seed)
    graph.add_node("brand_identify", _brand_identify)
    graph.add_node("brand_verify", _brand_verify)
    graph.add_node("brand_compare", _brand_compare)
    graph.add_node("brand_impersonation", _brand_impersonation)
    graph.add_node("behavior", _behavior)
    graph.add_node("plan", _plan)
    graph.add_node("execute", _execute)
    graph.add_node("finalize", _finalize)
    graph.add_edge(START, "seed")
    graph.add_edge("seed", "brand_identify")
    graph.add_edge("brand_identify", "brand_verify")
    graph.add_edge("brand_verify", "brand_compare")
    graph.add_edge("brand_compare", "brand_impersonation")
    graph.add_edge("brand_impersonation", "behavior")
    graph.add_edge("behavior", "plan")
    graph.add_conditional_edges("plan", _route_after_plan, {"execute": "execute", "finalize": "finalize"})
    graph.add_edge("execute", "plan")
    graph.add_edge("finalize", END)
    return graph.compile()


async def run_investigation(
    *,
    scan_id: str,
    user_id: str,
    url: str,
    browser_evidence: dict[str, Any],
    deterministic_findings: list[Any],
    unavailable: list[str],
    gate_reasons: list[str] | None = None,
) -> InvestigationResult:
    enabled, reasons = investigation_enabled(deterministic_findings, browser_evidence, unavailable, url)
    if not enabled:
        return InvestigationResult(unavailable=["investigation_skipped"], artifacts={"gate_reasons": reasons})
    state: InvestigationState = {
        "scan_id": scan_id,
        "user_id": user_id,
        "url": url,
        "browser_evidence": browser_evidence,
        "deterministic_findings": deterministic_findings,
        "unavailable": unavailable,
        "gate_reasons": gate_reasons or reasons,
    }
    result = await _compiled_graph().ainvoke(state)
    return InvestigationResult(
        findings=list(result.get("findings") or []),
        checks=list(result.get("checks") or []),
        unavailable=list(result.get("unavailable") or []),
        artifacts=dict(result.get("artifacts") or {}),
    )
