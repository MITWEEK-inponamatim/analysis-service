"""Image scanner entry point.

The pipeline itself lives in the LangGraph nodes (``app/graph/image.py``): bounded OCR,
optional vision, message analysis, and up to two extracted links through the URL scanner.
"""

from typing import Any

from .schemas import ScanReport

IMAGE_LIMITATIONS = [
    "OCR bisa salah membaca teks pada gambar; selalu verifikasi isi pesan secara manual.",
    "Gambar bisa diedit atau dipalsukan sebelum dikirim, sehingga tampilan tidak membuktikan aslinya.",
]


async def scan_image(scan_id: str, user_id: str, payload: dict[str, Any], options: dict[str, Any] | None = None) -> ScanReport:
    from .graph.image import build_image_graph
    from .graph.runner import run_graph

    state = {
        "scan_id": scan_id,
        "user_id": user_id,
        "payload": payload or {},
        "options": options or {},
    }
    result = await run_graph(build_image_graph, state, scan_id)
    return result["report"]
