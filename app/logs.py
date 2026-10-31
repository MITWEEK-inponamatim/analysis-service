"""Log redaction and setup (Fase 4 hardening, handoff 9).

Logs may carry scan ids and request ids, never tokens, API keys, or full message bodies.
This filter is a safety net: known credential shapes are masked even if a caller slips.
"""

import logging
import os
import re

MASK = "***"

_PATTERNS = (
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"), "sk-" + MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}"), MASK + "-jwt"),
    (re.compile(r"\b[A-Fa-f0-9]{64}\b"), MASK + "-hex64"),
    (re.compile(r"(?i)\b(Bearer)\s+[A-Za-z0-9._\-]{8,}"), r"\1 " + MASK),
    (re.compile(r"(?i)\b(apikey|api_key|secret|token|password|service_key)\b\s*[=:]\s*\S+"), r"\1=" + MASK),
    (re.compile(r"postgres(?:ql)?://[^\s\"']+"), "postgres://" + MASK),
)


def redact(text: str) -> str:
    if not text:
        return text
    result = str(text)
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            return True
        cleaned = redact(rendered)
        if cleaned != rendered:
            record.msg = cleaned
            record.args = ()
        return True


_configured = False


def configure_logging(level: str | None = None) -> None:
    """Attach the redacting filter once; safe to call from several entry points."""
    global _configured
    if _configured:
        return
    _configured = True
    resolved = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.addFilter(RedactingFilter())
    root.setLevel(resolved)
    if not root.handlers:
        root.addHandler(handler)
