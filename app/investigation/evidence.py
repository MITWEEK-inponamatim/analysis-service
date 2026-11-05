"""Normalized evidence store with stable IDs and observed/interpretation separation.

Evidence IDs are content-addressed within a scan, so identical observations dedupe
and no skill can invent an ID that the store did not create.
"""
import hashlib
import json
import re
from typing import Any, Iterable

REDACT_KEYS = {
    "authorization", "cookie", "set-cookie", "password", "passwd", "secret",
    "token", "api_key", "apikey", "access_token", "refresh_token",
}
TELEGRAM_BOT_TOKEN = re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}")
MAX_STRING = 4000
MAX_ITEMS = 400
KIND_RE = re.compile(r"^[a-z][a-z0-9_]{1,24}$")


class EvidenceError(ValueError):
    pass


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _redact(item)
            for key, item in value.items()
            if str(key).lower() not in REDACT_KEYS
        }
    if isinstance(value, list):
        return [_redact(item) for item in value[:100]]
    if isinstance(value, str):
        return TELEGRAM_BOT_TOKEN.sub("[REDACTED_TELEGRAM_BOT_TOKEN]", value[:MAX_STRING])
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:MAX_STRING]


class EvidenceStore:
    def __init__(self, scan_id: str, user_id: str):
        self.scan_id = scan_id
        self.user_id = user_id
        self._items: dict[str, dict[str, Any]] = {}

    def add(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        skill: str = "",
        observed: bool = True,
        fact: str = "",
    ) -> str:
        if not KIND_RE.match(kind):
            raise EvidenceError("invalid_evidence_kind")
        if len(self._items) >= MAX_ITEMS:
            raise EvidenceError("evidence_limit_reached")
        cleaned = _redact(payload or {})
        digest = hashlib.sha256(
            json.dumps(
                {"scan": self.scan_id, "kind": kind, "payload": cleaned},
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            ).encode()
        ).hexdigest()[:12]
        evidence_id = f"ev_{kind}_{digest}"
        self._items.setdefault(
            evidence_id,
            {
                "evidence_id": evidence_id,
                "kind": kind,
                "skill": skill,
                "observed": bool(observed),
                "fact": fact[:300],
                "payload": cleaned,
            },
        )
        return evidence_id

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        return self._items.get(evidence_id)

    def exists(self, evidence_id: str) -> bool:
        return evidence_id in self._items

    def index(self) -> dict[str, str]:
        return {
            evidence_id: f"{item['kind']}: {item['fact'] or _brief(item['payload'])}"
            for evidence_id, item in self._items.items()
        }

    def summaries(self, evidence_ids: Iterable[str]) -> list[dict[str, Any]]:
        result = []
        for evidence_id in evidence_ids:
            item = self._items.get(evidence_id)
            if item is not None:
                result.append(
                    {
                        "evidence_id": evidence_id,
                        "kind": item["kind"],
                        "fact": item["fact"],
                        "observed": item["observed"],
                        "payload": item["payload"],
                    }
                )
        return result

    def validate(self, evidence_ids: Iterable[str]) -> tuple[list[str], list[str]]:
        valid, invalid = [], []
        for evidence_id in evidence_ids:
            (valid if evidence_id in self._items else invalid).append(evidence_id)

        return valid, invalid


    def sanitize(self, payload: Any) -> Any:
        """Apply evidence redaction and size limits before report/persistence output."""
        return _redact(payload)

    def items(self) -> list[dict[str, Any]]:
        return list(self._items.values())


def _brief(payload: dict[str, Any]) -> str:
    keys = ", ".join(sorted(payload)[:6])
    return f"{keys}"[:200]
