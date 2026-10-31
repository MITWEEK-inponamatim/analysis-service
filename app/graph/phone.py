"""Phone graph: normalisation, community reports, then a deterministic assessment."""

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph


class PhoneState(TypedDict, total=False):
    scan_id: str
    number: str
    default_region: str
    e164: str
    carrier: str
    line_type: str
    region: str
    findings: list
    checks: list[str]
    unavailable: list[str]
    limitations: list[str]
    confidence: str
    evidence_suffix: str
    checkpointer_unavailable: bool
    report: Any


def build_phone_graph(checkpointer=None):
    from ..graph.runner import merge_checkpoint_flag
    from ..phone_scanner import PHONE_LIMITATIONS, PHONENUMBERS_AVAILABLE, _report_finding, fetch_reports, normalize_number
    from ..reporting import extend_unique
    from ..risk import assess, finding

    async def normalize(state: PhoneState):
        parsed = normalize_number(state.get("number", ""), state.get("default_region", "ID"))
        findings = []
        checks = ["phone_number_normalization"]
        unavailable = ["phone_reputation_service"]
        limitations = list(PHONE_LIMITATIONS)
        if not PHONENUMBERS_AVAILABLE:
            unavailable.append("phone_number_library")
            limitations.append("Pustaka normalisasi nomor tidak tersedia; normalisasi memakai aturan sederhana dan bisa kurang akurat.")
        if not parsed.valid:
            findings.append(finding(
                "Nomor tidak valid atau tidak wajar untuk region yang dipilih; hasil tidak dapat diverifikasi.",
                "phone_validation", "low",
                {"region": parsed.region or state.get("default_region", "ID"), "reasons": parsed.reasons},
                confidence="low",
            ))
            limitations.append("Nomor tidak valid sehingga pemeriksaan reputasi tidak dapat diandalkan.")
        if parsed.line_type == "premium_rate":
            findings.append(finding(
                "Nomor terdeteksi sebagai premium rate; nomor seperti ini sering dipakai untuk menarik biaya.",
                "phone_validation", "medium", {"line_type": parsed.line_type},
            ))
        return {"findings": findings, "checks": checks, "unavailable": unavailable, "limitations": limitations,
                "e164": parsed.e164, "confidence": "low",
                "carrier": parsed.carrier, "line_type": parsed.line_type, "region": parsed.region or state.get("default_region", "ID")}

    def after_normalize(state: PhoneState):
        return "reports" if state.get("e164") else "assess"

    async def reports(state: PhoneState):
        findings = list(state.get("findings") or [])
        checks = list(state.get("checks") or [])
        unavailable = list(state.get("unavailable") or [])
        limitations = list(state.get("limitations") or [])
        confidence = state.get("confidence", "low")
        rows = await fetch_reports(state.get("e164", ""))
        if rows is None:
            extend_unique(unavailable, ["phone_reports"])
            extend_unique(limitations, ["Sumber laporan komunitas tidak dapat dibaca, sehingga reputasi nomor belum diperiksa."])
        else:
            extend_unique(checks, ["phone_reports"])
            report_finding = _report_finding(state.get("e164", ""), rows)
            if report_finding:
                findings.append(report_finding)
                confidence = "medium"
            else:
                extend_unique(limitations, ["Tidak ada laporan komunitas untuk nomor ini; itu bukan bukti nomor aman."])
        return {"findings": findings, "checks": checks, "unavailable": unavailable, "limitations": limitations, "confidence": confidence}

    async def assess_state(state: PhoneState):
        findings = list(state.get("findings") or [])
        unavailable = list(state.get("unavailable") or [])
        merge_checkpoint_flag(unavailable, state)
        report = assess(
            state["scan_id"], "phone", findings,
            list(state.get("checks") or []), unavailable,
            {"model": "", "prompt_tokens": 0, "completion_tokens": 0, "latency_ms": 0, "status": "not_used"},
            limitations=list(state.get("limitations") or []),
            confidence=state.get("confidence", "low"),
        )
        if state.get("e164"):
            details = [f"Nomor dinormalisasi ke {state['e164']}"]
            if state.get("region"):
                details.append(f"region {state['region']}")
            if state.get("line_type") and state.get("line_type") != "unknown":
                details.append(f"jenis {state['line_type']}")
            if state.get("carrier"):
                details.append(f"operator (perkiraan prefix) {state['carrier']}")
            report.evidence_summary = f"{report.evidence_summary} {', '.join(details)}."
        return {"report": report}

    graph = StateGraph(PhoneState)
    graph.add_node("normalize", normalize)
    graph.add_node("reports", reports)
    graph.add_node("assess", assess_state)
    graph.add_edge(START, "normalize")
    graph.add_conditional_edges("normalize", after_normalize, {"reports": "reports", "assess": "assess"})
    graph.add_edge("reports", "assess")
    graph.add_edge("assess", END)
    return graph.compile(checkpointer=checkpointer)
