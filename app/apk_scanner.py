"""Application scanner entry point.

The pipeline lives in ``app/graph/application.py``: zip-bomb pre-check, hash reputation
(VirusTotal, optional), isolated Androguard extraction, optional MobSF, and a bounded agent
review. The APK is never executed and never uploaded without ``consent_external_upload``.
"""

from typing import Any

from .schemas import ScanReport

APK_LIMITATIONS = [
    "Hash yang tidak dikenal bukan berarti berkas aman; hanya berarti belum ada laporan publik untuk sampel tersebut.",
    "Analisis statis tidak menjalankan APK, sehingga perilaku runtime (mis. koneksi ke server penyerang) tidak teramati.",
    "APK yang di-obfuscate atau di-pack dapat menyembunyikan perilakunya dari analisis statis.",
]


async def scan_application(scan_id: str, user_id: str, payload: dict[str, Any], options: dict[str, Any] | None = None) -> ScanReport:
    from .graph.application import build_application_graph
    from .graph.runner import run_graph

    state = {
        "scan_id": scan_id,
        "user_id": user_id,
        "payload": payload or {},
        "options": options or {},
    }
    result = await run_graph(build_application_graph, state, scan_id)
    return result["report"]
