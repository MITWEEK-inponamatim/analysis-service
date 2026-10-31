"""Image graph: bounded OCR, optional vision, message analysis, then extracted links."""

import asyncio
import os
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

MAX_IMAGE_ITERATIONS = 1


class ImageState(TypedDict, total=False):
    scan_id: str
    user_id: str
    payload: dict
    options: dict
    data: bytes
    mime: str
    filename: str
    ocr_text: str
    ocr_available: bool
    ocr_meta: dict
    urls: list[str]
    iterations: int
    findings: list
    checks: list[str]
    unavailable: list[str]
    limitations: list[str]
    artifacts: dict
    usage: dict
    checkpointer_unavailable: bool
    report: Any


def _url_limit() -> int:
    try:
        value = int(os.getenv("IMAGE_URL_SCAN_LIMIT", "2"))
    except ValueError:
        value = 2
    return max(0, min(value, 3))


def _url_timeout() -> float:
    try:
        value = float(os.getenv("IMAGE_URL_SCAN_TIMEOUT_SECONDS", "35"))
    except ValueError:
        value = 35.0
    return max(5.0, min(value, 60.0))


def build_image_graph(checkpointer=None):
    from .. import storage
    from ..agent import run_agent
    from ..file_client import analyze_file
    from ..graph.runner import merge_checkpoint_flag
    from ..heuristics import message_terms
    from ..indicators import extract_urls
    from ..reporting import extend_unique, prefixed
    from ..risk import assess, fail_report, finding
    from ..scanners import DEFAULT_MESSAGE_ANALYSIS_PROMPT, default_usage, scan_url_pipeline
    from ..tools import ToolContext
    from ..vision import analyze_image as vision_analyze

    limit_mb = int(os.getenv("MAX_IMAGE_MB", "15"))

    def _image_limitations() -> list[str]:
        return [
            "OCR bisa salah membaca teks pada gambar; selalu verifikasi isi pesan secara manual.",
            "Gambar bisa diedit atau dipalsukan sebelum dikirim, sehingga tampilan tidak membuktikan aslinya.",
        ]

    async def load(state: ImageState):
        payload = state.get("payload") or {}
        try:
            data = await storage.download_object(
                str(payload.get("bucket") or "uploads"),
                str(payload.get("storage_path") or ""),
                state["user_id"], state["scan_id"],
                max_bytes=limit_mb << 20,
            )
        except storage.UnsafeStoragePath:
            return {"report": fail_report(state["scan_id"], "image", "unsafe_storage_path", "Objek unggahan tidak berada pada folder scan milik pengguna ini.", checks_unavailable=["storage_read"])}
        except storage.StorageUnavailable:
            return {"report": fail_report(state["scan_id"], "image", "storage_unavailable", "Berkas gambar tidak dapat diambil untuk dianalisis.", checks_unavailable=["storage_read"])}
        return {
            "data": data,
            "mime": str(payload.get("mime") or "image/png"),
            "filename": str(payload.get("filename") or "upload"),
            "checks": ["storage_read"],
            "unavailable": [],
            "findings": [],
            "limitations": _image_limitations(),
            "artifacts": {"screenshot_path": None, "redirect_chain": []},
            "usage": {},
            "iterations": 0,
        }

    def after_load(state: ImageState):
        return "assess" if state.get("report") is not None else "ocr"

    async def ocr(state: ImageState):
        extraction = await analyze_file("image", state.get("data") or b"", state.get("filename", ""), state.get("mime", "image/png"))
        text = str(extraction.get("text") or "")
        available = bool(extraction.get("available"))
        artifacts = dict(state.get("artifacts") or {})
        artifacts["ocr"] = {"available": available, "reason": extraction.get("reason"), "languages": extraction.get("languages"), "characters": len(text)}
        checks = list(state.get("checks") or [])
        unavailable = list(state.get("unavailable") or [])
        limitations = list(state.get("limitations") or [])
        if available:
            extend_unique(checks, ["ocr"])
            if not text.strip():
                extend_unique(limitations, ["Tidak ada teks yang terdeteksi pada gambar; analisis isi tidak dapat dilakukan."])
        else:
            extend_unique(unavailable, ["ocr"])
            extend_unique(limitations, ["OCR gagal atau tidak tersedia, sehingga isi gambar tidak dapat dianalisis."])
        return {"ocr_text": text, "ocr_available": available, "checks": checks, "unavailable": unavailable, "limitations": limitations, "artifacts": artifacts}

    async def analyze(state: ImageState):
        text = state.get("ocr_text") or ""
        findings = list(state.get("findings") or [])
        checks = list(state.get("checks") or [])
        unavailable = list(state.get("unavailable") or [])
        limitations = list(state.get("limitations") or [])
        artifacts = dict(state.get("artifacts") or {})
        usage = dict(state.get("usage") or {})
        urls: list[str] = []
        if not text.strip():
            return {"findings": findings, "checks": checks, "unavailable": unavailable, "limitations": limitations, "artifacts": artifacts, "usage": usage, "urls": urls}

        extend_unique(checks, ["message_heuristics"])
        for term in message_terms(text):
            findings.append(finding(f"Teks pada gambar memuat indikator rekayasa sosial: {term}", "heuristic", "medium", {"term": term}))

        context = ToolContext(scan_id=state["scan_id"], user_id=state["user_id"], kind="image", ocr_text=text, message=text, file_ids=[state["scan_id"]])
        result = await run_agent(context, system_prompt=DEFAULT_MESSAGE_ANALYSIS_PROMPT, payload=text[:8000])
        if result is None:
            extend_unique(unavailable, ["llm_analysis"])
        else:
            for item in result.findings:
                findings.append(finding(item.indicator, "llm_analysis", item.severity, confidence=item.confidence))
            extend_unique(unavailable, result.unavailable or [])
            if result.usage.get("status") == "completed":
                extend_unique(checks, ["llm_analysis"])
                usage = result.usage
            if result.tool_calls:
                extend_unique(checks, ["llm_tool_calls"])

        vision = await vision_analyze(state.get("data") or b"", state.get("mime") or "image/png")
        if vision is None:
            extend_unique(unavailable, ["llm_vision"])
            extend_unique(limitations, ["Analisis gambar dengan model vision tidak aktif; penilaian hanya memakai OCR."])
        elif vision.get("error"):
            extend_unique(unavailable, ["llm_vision"])
            extend_unique(limitations, [f"Model vision tidak dapat dipakai ({vision['error']})."])
        else:
            extend_unique(checks, ["llm_vision"])
            for item in vision.get("findings") or []:
                findings.append(finding(item.indicator, "llm_vision", item.severity, confidence=item.confidence))
            if not usage:
                usage = vision.get("usage") or {}

        from .. import exa

        if not exa.available():
            extend_unique(unavailable, ["exa_search"])
            extend_unique(limitations, ["Verifikasi klaim dengan Exa tidak dijalankan karena layanan itu belum dikonfigurasi."])

        urls = extract_urls(text, limit=_url_limit())
        if urls:
            from urllib.parse import urlsplit

            from ..brand_guard import brand_findings

            extend_unique(checks, ["brand_guard"])
            for url in urls:
                findings.extend(brand_findings(urlsplit(url).hostname or ""))
            extend_unique(limitations, ["Tautan pada gambar diperiksa dengan scanner URL bila memungkinkan."])
        return {
            "findings": findings,
            "checks": checks,
            "unavailable": unavailable,
            "limitations": limitations,
            "artifacts": artifacts,
            "usage": usage,
            "urls": urls,
        }

    def after_analyze(state: ImageState):
        if state.get("urls") and int(state.get("iterations", 0)) < MAX_IMAGE_ITERATIONS:
            return "collect_urls"
        return "assess"

    async def collect_urls(state: ImageState):
        findings = list(state.get("findings") or [])
        checks = list(state.get("checks") or [])
        unavailable = list(state.get("unavailable") or [])
        limitations = list(state.get("limitations") or [])
        artifacts = dict(state.get("artifacts") or {})
        seen = {item.id for item in findings}
        for index, url in enumerate((state.get("urls") or [])[:_url_limit()]):
            label = url.split("/")[2] if url.count("/") >= 2 else url[:80]
            try:
                subreport = await asyncio.wait_for(
                    scan_url_pipeline(state["scan_id"], url, state["user_id"]),
                    timeout=_url_timeout(),
                )
            except Exception:
                extend_unique(unavailable, ["url_scan"])
                extend_unique(limitations, [f"Pemeriksaan URL {label} tidak selesai dalam batas waktu; tautan perlu diperiksa terpisah."])
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
        return {"findings": findings, "checks": checks, "unavailable": unavailable, "limitations": limitations, "artifacts": artifacts, "iterations": int(state.get("iterations", 0)) + 1}

    async def assess_state(state: ImageState):
        if state.get("report") is not None:
            return {"report": state["report"]}
        findings = list(state.get("findings") or [])
        checks = list(state.get("checks") or [])
        unavailable = list(state.get("unavailable") or [])
        limitations = list(state.get("limitations") or [])
        merge_checkpoint_flag(unavailable, state)
        if (state.get("ocr_text") or "").strip() and not (state.get("urls") or []):
            extend_unique(limitations, ["Tidak ada tautan yang dapat diekstrak dari teks pada gambar."])
        if not findings:
            extend_unique(limitations, ["Tidak ditemukannya indikator bukan bukti gambar aman."])
        usage = state.get("usage") or default_usage()
        report = assess(
            state["scan_id"], "image", findings, checks, unavailable, usage,
            limitations=limitations, artifacts=state.get("artifacts") or None,
        )
        report.evidence_summary = f"{len(state.get('ocr_text') or '')} karakter teks dibaca dari gambar. {report.evidence_summary}"
        return {"report": report}

    graph = StateGraph(ImageState)
    graph.add_node("load_object", load)
    graph.add_node("run_ocr", ocr)
    graph.add_node("analyze", analyze)
    graph.add_node("collect_urls", collect_urls)
    graph.add_node("assess", assess_state)
    graph.add_edge(START, "load_object")
    graph.add_conditional_edges("load_object", after_load, {"ocr": "run_ocr", "assess": "assess"})
    graph.add_edge("run_ocr", "analyze")
    graph.add_conditional_edges("analyze", after_analyze, {"collect_urls": "collect_urls", "assess": "assess"})
    graph.add_edge("collect_urls", "assess")
    graph.add_edge("assess", END)
    return graph.compile(checkpointer=checkpointer)
