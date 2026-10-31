"""Helpers for merging evidence collected by several graph nodes into one report."""

from typing import Any

from .risk import assess, finding
from .schemas import Finding, ScanReport


def prefixed(prefix: str, items: list[Finding], seen: set[str]) -> list[Finding]:
    """Copy findings under a host/step prefix so ids stay unique and provenance is visible."""
    merged: list[Finding] = []
    for item in items:
        copy = finding(f"{prefix}: {item.indicator}", item.source, item.severity, dict(item.metadata), confidence=item.confidence)
        if copy.id in seen:
            continue
        seen.add(copy.id)
        merged.append(copy)
    return merged


def extend_unique(target: list[str], extra: list[str]) -> None:
    for item in extra:
        if item not in target:
            target.append(item)


def rebuild(
    report: ScanReport,
    *,
    findings: list[Finding] | None = None,
    checks_run: list[str] | None = None,
    checks_unavailable: list[str] | None = None,
    limitations: list[str] | None = None,
    artifacts: dict[str, Any] | None = None,
) -> ScanReport:
    """Recompute outcome/risk from a combined finding set, preserving scan metadata."""
    merged_findings = list(findings if findings is not None else report.findings)
    runs = list(report.risk.get("coverage", {}).get("checks_run", []))
    unavailable = list(report.risk.get("coverage", {}).get("checks_unavailable", []))
    if checks_run:
        extend_unique(runs, checks_run)
    if checks_unavailable:
        extend_unique(unavailable, checks_unavailable)
    merged_limitations = list(report.limitations)
    if limitations:
        extend_unique(merged_limitations, limitations)
    merged_artifacts = dict(report.artifacts)
    if artifacts:
        merged_artifacts.update(artifacts)
    rebuilt = assess(
        report.scan_id,
        report.type,
        merged_findings,
        runs,
        unavailable,
        report.llm_usage,
        limitations=merged_limitations,
        artifacts=merged_artifacts,
        confidence=report.risk.get("confidence"),
    )
    rebuilt.evidence_summary = report.evidence_summary
    rebuilt.error = report.error
    return rebuilt
