"""URL graph: SSRF validation, evidence collection, and one bounded deep-check pass.

Deep checks are conditional and iteration-bounded: when the page redirects to another host,
or posts a form to another host, the graph runs reputation lookups against those destinations
(without a second browser session). That is the "LangGraph kondisional lanjutan" step.
"""

from typing import Any, TypedDict
from urllib.parse import urlsplit

from langgraph.graph import END, START, StateGraph

MAX_URL_ITERATIONS = 2
MAX_DEEP_TARGETS = 2


class URLState(TypedDict, total=False):
    scan_id: str
    user_id: str
    url: str
    iterations: int
    url_safe: bool
    visited: list[str]
    checkpointer_unavailable: bool
    report: Any


def _host(value: str) -> str:
    try:
        return (urlsplit(value).hostname or "").casefold().rstrip(".")
    except ValueError:
        return ""


def _final_url(report: Any, original: str) -> str:
    artifacts = getattr(report, "artifacts", {}) or {}
    candidate = str(artifacts.get("final_url") or "")
    if not candidate:
        chain = artifacts.get("redirect_chain") or []
        if chain:
            candidate = str((chain[-1] or {}).get("url") or "")
    return candidate or original


def _targets(state: URLState) -> list[tuple[str, str]]:
    """Destinations worth a reputation-only pass: redirect target and form actions."""
    report = state.get("report")
    if report is None:
        return []
    original_host = _host(state.get("url", ""))
    visited = {value.casefold() for value in (state.get("visited") or [])}
    artifacts = getattr(report, "artifacts", {}) or {}
    candidates: list[tuple[str, str]] = []
    final_url = _final_url(report, state.get("url", ""))
    if final_url and final_url != state.get("url") and _host(final_url) not in ("", original_host):
        candidates.append(("Tujuan redirect", final_url))
    for action in (artifacts.get("form_actions") or [])[:5]:
        if _host(action) in ("", original_host):
            continue
        candidates.append(("Tujuan formulir", str(action)))
    selected: list[tuple[str, str]] = []
    seen_hosts: set[str] = set()
    for role, target in candidates:
        host = _host(target)
        key = target.casefold()
        if not host or host in seen_hosts or key in visited:
            continue
        seen_hosts.add(host)
        selected.append((role, target))
        if len(selected) >= MAX_DEEP_TARGETS:
            break
    return selected


def build_url_graph(checkpointer=None):
    from ..browser_guard import UnsafeTarget, validate_target
    from ..reporting import extend_unique, prefixed, rebuild
    from ..scanners import scan_url_pipeline

    async def validate(state: URLState):
        try:
            await validate_target(state["url"])
            return {"url_safe": True}
        except (UnsafeTarget, ValueError, TimeoutError, OSError):
            return {"url_safe": False}

    async def analyze(state: URLState):
        report = await scan_url_pipeline(
            state["scan_id"], state["url"], state["user_id"],
            state.get("checkpointer_unavailable", False),
            validation_result=True,
        )
        return {"report": report, "iterations": 1, "visited": [state.get("url", "")]}

    async def blocked(state: URLState):
        report = await scan_url_pipeline(
            state["scan_id"], state["url"], state["user_id"],
            state.get("checkpointer_unavailable", False),
            validation_result=False,
        )
        return {"report": report, "iterations": 1}

    async def deep_checks(state: URLState):
        report = state["report"]
        targets = _targets(state)
        if not targets:
            return {"report": report, "iterations": int(state.get("iterations", 1)) + 1}
        findings = list(report.findings)
        seen = {item.id for item in findings}
        checks: list[str] = []
        unavailable: list[str] = []
        limitations = [f"Pemeriksaan tambahan dilakukan pada {len(targets)} tujuan: {', '.join(sorted({_host(target) for _, target in targets}))}."]
        for role, target in targets:
            extra = await scan_url_pipeline(
                state["scan_id"], target, state["user_id"],
                state.get("checkpointer_unavailable", False),
                inspect_browser=False,
            )
            if "public_dns_validation" in extra.risk.get("coverage", {}).get("checks_unavailable", []):
                extend_unique(unavailable, ["deep_target_validation"])
                extend_unique(limitations, [f"{role} {_host(target)} tidak dapat diperiksa karena alamatnya non-publik."])
                continue
            prefix = f"{role} {_host(target)}"
            findings.extend(prefixed(prefix, extra.findings, seen))
            extend_unique(checks, extra.risk.get("coverage", {}).get("checks_run", []))
            extend_unique(unavailable, extra.risk.get("coverage", {}).get("checks_unavailable", []))
            extend_unique(limitations, extra.limitations)
        merged = rebuild(report, findings=findings, checks_run=checks, checks_unavailable=unavailable, limitations=limitations)
        visited = list(state.get("visited") or []) + [target for _, target in targets]
        return {"report": merged, "iterations": int(state.get("iterations", 1)) + 1, "visited": visited}

    def after_validation(state: URLState):
        return "analyze" if state.get("url_safe") else "blocked"

    def after_analyze(state: URLState):
        if state.get("report") is None:
            return "done"
        if int(state.get("iterations", 1)) >= MAX_URL_ITERATIONS:
            return "done"
        return "deep" if _targets(state) else "done"

    graph = StateGraph(URLState)
    graph.add_node("validate_url", validate)
    graph.add_node("url_analysis", analyze)
    graph.add_node("blocked_url", blocked)
    graph.add_node("deep_checks", deep_checks)
    graph.add_edge(START, "validate_url")
    graph.add_conditional_edges("validate_url", after_validation, {"analyze": "url_analysis", "blocked": "blocked_url"})
    graph.add_conditional_edges("url_analysis", after_analyze, {"deep": "deep_checks", "done": END})
    graph.add_edge("blocked_url", END)
    graph.add_edge("deep_checks", END)
    return graph.compile(checkpointer=checkpointer)
