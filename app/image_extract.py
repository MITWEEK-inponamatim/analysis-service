"""OCR extraction for untrusted screenshots.

Images are user-supplied, so decoding is bounded: format allowlist, pixel budget, and a
timeout around the OCR call. Runs inside the isolated ``analysis-worker`` container.
"""

import io
import os
import shutil

ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP"}
MAX_PIXELS = 40_000_000
MAX_TEXT_CHARS = 20000


def _ocr_languages() -> str:
    return os.getenv("OCR_LANGUAGES", "ind+eng")


def extract_image_text(data: bytes) -> dict:
    """Return {"available", "reason", "text", "languages", "format", "pixels"}."""
    result: dict = {"available": False, "reason": None, "text": "", "languages": "", "format": None, "pixels": 0}
    try:
        from PIL import Image

        Image.MAX_IMAGE_PIXELS = MAX_PIXELS
        image = Image.open(io.BytesIO(data))
        result["format"] = image.format
        if image.format not in ALLOWED_FORMATS:
            result["reason"] = "unsupported_image_format"
            return result
        width, height = image.size
        result["pixels"] = width * height
        if width * height > MAX_PIXELS:
            result["reason"] = "image_dimensions_too_large"
            return result
        image.load()
        prepared = image.convert("L")
    except ImportError:
        result["reason"] = "pillow_missing"
        return result
    except Exception:
        result["reason"] = "image_unreadable"
        return result

    try:
        import pytesseract
    except ImportError:
        result["reason"] = "pytesseract_missing"
        return result
    if not shutil.which("tesseract") and os.getenv("TESSERACT_CMD", "") == "":
        result["reason"] = "tesseract_binary_missing"
        return result

    for languages in (_ocr_languages(), "eng"):
        try:
            text = pytesseract.image_to_string(prepared, lang=languages, timeout=float(os.getenv("OCR_TIMEOUT_SECONDS", "20")))
        except Exception:
            continue
        result.update(available=True, reason=None, text=text[:MAX_TEXT_CHARS].strip(), languages=languages)
        return result
    result["reason"] = "ocr_failed"
    return result
