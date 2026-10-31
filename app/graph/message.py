"""Message graph: deterministic indicators, bounded agent analysis, then extracted links."""

import os
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

MAX_MESSAGE_ITERATIONS = 1
URL_SCAN_TIMEOUT_SECONDS = 35.0


class MessageState(TypedDict, total=False):
    scan_id: str
    user_id: str
    text: str
    iterations: int
    findings: list
    checks: list[str]
    unavailable: list[str]
    limitations: list[str]
    usage: dict
    urls: list[str]
    artifacts: dict
    checkpointer_unavailable: bool
    report: Any


def _url_limit() -> int:
    try:
        value = int(os.getenv("MESSAGE_URL_SCAN_LIMIT", "2"))
    except ValueError:
        value = 2
    return max(0, min(value, 3))


def build_message_graph(checkpointer=None):
    import asyncio

    from ..graph.runner import merge_checkpoint_flag
    from ..heuristics import message_terms
    from ..indicators import extract_urls
    from ..reporting import extend_unique, prefixed
    from ..risk import assess, finding
    from ..scanners import analyze_message_text, scan_url_pipeline

    async def prepare(state: MessageState):
        from urllib.parse import urlsplit

        from ..brand_guard import brand_findings

        text = state.get("text") or ""
        findings = [
            finding(f"Pesan mengandung indikator rekayasa sosial: {term}", "heuristic", "medium", {"term": term})
            for term in message_terms(text)
        ]
        checks = ["message_heuristics"]
        limitations: list[str] = []
        artifacts = {"screenshot_path": None, "redirect_chain": []}
        urls = extract_urls(text, limit=_url_limit())
        if urls:
            artifacts["urls"] = urls
            checks.append("brand_guard")
            for url in urls:
                findings.extend(brand_findings(urlsplit(url).hostname or ""))
        return {
            "findings": findings,
            "checks": checks,
            "unavailable": [],
            "limitations": limitations,
            "urls": urls,
            "usage": {},
            "artifacts": artifacts,
            "iterations": 0,
        }

    async def analyze(state: MessageState):
        from .. import exa

        result = await analyze_message_text(state["scan_id"], state.get("text") or "")
        findings = list(state.get("findings") or []) + list(result["findings"])
        checks = list(state.get("checks") or [])
        unavailable = list(state.get("unavailable") or [])
        limitations = list(state.get("limitations") or [])
        extend_unique(checks, [name for name in result["checks"] if name not in checks])
        extend_unique(unavailable, result["unavailable"])
        merge_checkpoint_flag(unavailable, state)
        if (state.get("text") or "").strip() and not exa.available():
            extend_unique(unavailable, ["exa_search"])
            extend_unique(limitations, ["Verifikasi klaim dengan Exa tidak dijalankan karena layanan itu belum dikonfigurasi."])
        return {"findings": findings, "checks": checks, "unavailable": unavailable, "limitations": limitations, "usage": result["usage"]}

    def after_analyze(state: MessageState):
        if state.get("urls") and int(state.get("iterations", 0)) < MAX_MESSAGE_ITERATIONS:
            return "collect_urls"
        return "assess"

    async def collect_urls(state: MessageState):
        findings = list(state.get("findings") or [])
        checks = list(state.get("checks") or [])
        unavailable = list(state.get("unavailable") or [])
        limitations = list(state.get("limitations") or [])
        artifacts = dict(state.get("artifacts") or {})
        seen = {item.id for item in findings}
        for index, url in enumerate((state.get("urls") or [])[:_url_limit()]):
            label = url.split("/")[2] if url.count("/") >= 2 else url[:80]
            try:
                subreport = await asyncio.wait_for(scan_url_pipeline(state["scan_id"], url, state.get("user_id", "")), timeout=URL_SCAN_TIMEOUT_SECONDS)
            except Exception:
                extend_unique(unavailable, ["url_scan"])
                extend_unique(limitations, [f"Pemeriksaan tautan {label} tidak selesai dalam batas waktu; periksa manual."])
                continue
            extend_unique(checks, ["url_scan"])
            findings.extend(prefixed(f"Tautan {label}", subreport.findings, seen))
            for name in subreport.risk.get("coverage", {}).get("checks_unavailable", []):
                extend_unique(unavailable, [f"url_{name}"])
            for limitation in subreport.limitations:
                extend_unique(limitations, [limitation])
            if index == 0 and subreport.artifacts.get("screenshot_path") and not artifacts.get("screenshot_path"):
                artifacts["screenshot_path"] = subreport.artifacts["screenshot_path"]
                artifacts["redirect_chain"] = subreport.artifacts.get("redirect_chain") or []
        return {
            "findings": findings,
            "checks": checks,
            "unavailable": unavailable,
            "limitations": limitations,
            "artifacts": artifacts,
            "iterations": int(state.get("iterations", 0)) + 1,
        }

    async def assess_state(state: MessageState):
        findings = list(state.get("findings") or [])
        checks = list(state.get("checks") or [])
        unavailable = list(state.get("unavailable") or [])
        limitations = list(state.get("limitations") or [])
        merge_checkpoint_flag(unavailable, state)
        if not findings:
            extend_unique(limitations, ["Pemeriksaan heuristik terbatas; tidak ditemukannya indikator bukan bukti aman."])
        report = assess(
            state["scan_id"], "message", findings, checks, unavailable,
            state.get("usage") or None,
            limitations=limitations,
            artifacts=state.get("artifacts") or None,
        )
        return {"report": report}

    graph = StateGraph(MessageState)
    graph.add_node("prepare", prepare)
    graph.add_node("analyze", analyze)
    graph.add_node("collect_urls", collect_urls)
    graph.add_node("assess", assess_state)
    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "analyze")
    graph.add_conditional_edges("analyze", after_analyze, {"collect_urls": "collect_urls", "assess": "assess"})
    graph.add_edge("collect_urls", "assess")
    graph.add_edge("assess", END)
    return graph.compile(checkpointer=checkpointer)
