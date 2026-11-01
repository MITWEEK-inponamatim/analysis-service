"""Just-in-time skill loader.

Agents reference skills by exact allowlisted name. They never supply paths, URLs,
or file names, and the loader refuses anything outside the skills directory.
"""
import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "skills"
MAX_SKILL_CHARS = int(os.getenv("SKILL_MAX_CHARS", "12000"))
AGENT_GATEWAYS = {
    "brand": "brand-investigation-gateway",
    "behavior": "behavior-investigation-gateway",
}
_FRONTMATTER = re.compile(r"^---\n(.*?)\n---\n", re.S)
_FIELD = re.compile(r"^(name|description|layer|agent|version):\s*(.+)$", re.M)


class SkillError(ValueError):
    pass


def skills_root() -> Path:
    override = os.getenv("SKILLS_DIR", "").strip()
    return Path(override).resolve() if override else DEFAULT_ROOT


@lru_cache(maxsize=4)
def _allowlist(path: str) -> dict[str, Any]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise SkillError("skill_allowlist_unavailable") from exc


def allowlist() -> dict[str, Any]:
    return _allowlist(str(skills_root() / "allowlist.json"))


def clear_cache() -> None:
    _allowlist.cache_clear()
    _skill_text.cache_clear()


def _entry_agents(entry: dict[str, Any]) -> set[str]:
    declared = entry.get("agents")
    if isinstance(declared, list) and declared:
        return {str(item) for item in declared}
    return {str(entry.get("agent") or "")}


def _entries() -> dict[str, dict[str, Any]]:
    return {entry["name"]: entry for entry in allowlist().get("skills", []) if isinstance(entry, dict) and entry.get("name")}


def names() -> list[str]:
    return sorted(_entries())


def core_skills() -> list[str]:
    return [str(name) for name in allowlist().get("core", [])]


def gateway_for(agent: str) -> str:
    gateway = AGENT_GATEWAYS.get(agent)
    if not gateway:
        raise SkillError("unknown_agent")
    return gateway


def catalog_for(agent: str) -> list[dict[str, str]]:
    """Skills this agent may load, with a one-line description from frontmatter."""
    entries = _entries()
    catalog = []
    for name, entry in entries.items():
        if agent not in _entry_agents(entry):
            continue
        if entry.get("layer") == "orchestration":
            continue
        front = _frontmatter(load_skill(name))
        catalog.append(
            {
                "name": name,
                "layer": str(entry.get("layer") or ""),
                "description": front.get("description", "")[:300],
            }
        )
    return sorted(catalog, key=lambda item: (item["layer"] != "gateway", item["name"]))


def _frontmatter(text: str) -> dict[str, str]:
    match = _FRONTMATTER.match(text)
    if not match:
        raise SkillError("invalid_skill_frontmatter")
    return {key: value.strip().strip('"') for key, value in _FIELD.findall(match.group(1))}


@lru_cache(maxsize=32)
def _skill_text(path: str, modified: int) -> str:
    del modified
    return Path(path).read_text(encoding="utf-8")[:MAX_SKILL_CHARS]


def load_skill(name: str, agent: str | None = None) -> str:
    """Load one allowlisted skill by exact name. Raises SkillError on any mismatch."""
    entry = _entries().get(name)
    if entry is None:
        raise SkillError("skill_not_allowlisted")
    if agent and agent not in _entry_agents(entry):
        raise SkillError("skill_not_allowed_for_agent")
    root = skills_root()
    path = (root / str(entry.get("path") or "")).resolve()
    if root not in path.parents:
        raise SkillError("skill_path_escape")
    if not path.is_file():
        raise SkillError("skill_file_missing")
    return _skill_text(str(path), path.stat().st_mtime_ns)


def metadata(name: str) -> dict[str, str]:
    return _frontmatter(load_skill(name))
