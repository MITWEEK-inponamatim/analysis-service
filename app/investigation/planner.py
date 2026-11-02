"""Gap-driven investigation planner.

Deterministic by design: the planner selects allowlisted skills from evidence gaps.
No LLM decides what may run.
"""
import os
from typing import Any, Iterable

from . import deterministic as det
from . import skills
from .envelopes import PlanEnvelope, PlanStep, SkillEnvelope

MAX_STEPS = 4
MAX_ROUNDS = int(os.getenv("MAX_INVESTIGATION_ROUNDS", "2"))


def _agent_for(skill: str) -> str:
    entry = next((item for item in skills.allowlist().get("skills", []) if item.get("name") == skill), {})
    return str(entry.get("agent") or "behavior")


def _has_gap(envelope: SkillEnvelope, name: str) -> bool:
    return name in envelope.gaps or name in envelope.unavailable


def build_plan(
    *,
    store: Any,
    executor: Any,
    brand: SkillEnvelope,
    behavior: SkillEnvelope,
    round_number: int,
    max_rounds: int = MAX_ROUNDS,
) -> PlanEnvelope:
    if round_number >= max_rounds:
        return PlanEnvelope(status="stopped", stop_reason="max_rounds_reached")

    browser = executor.browser
    page_host = executor.page_host
    forms = det.sensitive_forms(browser, page_host)
    links = det.login_candidates(browser.get("links") or [], page_host)
    redirects = det.redirect_facts(browser.get("redirect_chain") or [], page_host)
    executed = set(executor.executed)

    questions: list[dict[str, Any]] = []
    candidates: list[tuple[str, str, str, dict[str, Any]]] = []

    def add(skill: str, question: str, reason: str, priority: str = "high", params: dict[str, Any] | None = None) -> None:
        questions.append({"question": question, "gap_reason": reason, "priority": priority})
        candidates.append((skill, question, reason, params or {}))

    claimed_brand = bool((brand.evidence_ids and not _has_gap(brand, "brand_unresolved")))
    if not claimed_brand and "inspect-page-content" not in executed:
        add("inspect-page-content", "Brand apa yang diklaim situs?", "identity_not_indexed", "high")
    if _has_gap(brand, "official_domain_unverified") and "investigate-brand-impersonation" not in executed:
        add("investigate-brand-impersonation", "Apakah domain resmi brand terverifikasi?", "official_domain_unverified", "high")
    if forms and "investigate-form-destination" not in executed:
        add("investigate-form-destination", "Ke mana data formulir dikirim?", "form_destination_unknown", "high")
    if redirects["registrable_domain_changes"] and "investigate-redirect-chain" not in executed:
        add("investigate-redirect-chain", "Apakah rantai redirect berpindah domain?", "redirect_chain_unanalyzed", "high")
    if not browser.get("network_requests") and "inspect-network-activity" not in executed:
        add("inspect-network-activity", "Host apa yang dihubungi halaman?", "network_empty", "medium")
    if (browser.get("js_obfuscation") or {}).get("detected") and "inspect-javascript-behavior" not in executed:
        add("inspect-javascript-behavior", "Apa perilaku JavaScript halaman?", "javascript_unanalyzed", "medium")
    if browser.get("iframes") and "inspect-embedded-content" not in executed:
        add("inspect-embedded-content", "Konten apa yang tertanam dan dari mana?", "embedded_content_unanalyzed", "medium")
    external = {det.normalize_host(str(item.get("url") or "")) for item in (browser.get("network_requests") or []) if isinstance(item, dict)}
    external.discard(page_host)
    if external and "investigate-external-domains" not in executed:
        add("investigate-external-domains", "Apa peran domain eksternal?", "external_domains_unattributed", "medium")
    if not forms and links and executor.traversals == 0:
        add(
            "inspect-navigation",
            "Apakah alur login berada di halaman berikutnya?",
            "multi_step_flow_candidate",
            "medium",
            {"url": links[0]["url"]},
        )

    if not candidates:
        return PlanEnvelope(
            status="completed",
            known_facts=[{"fact": item.fact, "evidence_ids": [item.evidence_id]} for env in (brand, behavior) for item in env.observations],
            open_questions=[],
            plan=[],
            stop_reason="no_open_gap",
            budget={"round": round_number, "executed_skills": sorted(executed)},
        )

    plan: list[PlanStep] = []
    seen: set[str] = set()
    for index, (skill, _question, reason, params) in enumerate(candidates[:MAX_STEPS], start=1):
        key = f"{skill}:{params.get('url', '')}"
        if key in seen:
            continue
        seen.add(key)
        plan.append(
            PlanStep(
                step=index,
                agent=_agent_for(skill),  # type: ignore[arg-type]
                skill=skill,
                reason=reason,
                expected_evidence=[skill.replace("inspect-", "").replace("investigate-", "")],
                params=params,
            )
        )
    return PlanEnvelope(
        status="completed" if round_number < max_rounds else "partial",
        known_facts=[{"fact": item.fact, "evidence_ids": [item.evidence_id]} for env in (brand, behavior) for item in env.observations],
        open_questions=questions[:MAX_STEPS],
        plan=plan,
        stop_reason=None if round_number < max_rounds else "max_rounds_reached",
        budget={"round": round_number, "executed_skills": sorted(executed)},
    )


def plans_for_agent(plan: PlanEnvelope, agent: str) -> Iterable[PlanStep]:
    return [step for step in plan.plan if step.agent == agent]
