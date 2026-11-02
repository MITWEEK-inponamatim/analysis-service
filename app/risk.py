from datetime import datetime, timezone
from typing import Any

from .schemas import Finding, ScanReport, Coverage, ComponentStatus

CONFIRMED_SOURCES = {"safe_browsing", "virustotal"}

# Calibration model (handoff 7.7 / Fase 4). Deterministic, no LLM input: each finding
# contributes a probability-like weight, the residual safety is multiplied down, and the
# result is capped when coverage is thin so a single weak source cannot say "high".
SEVERITY_WEIGHT = {"critical": 95, "high": 82, "medium": 40, "low": 12, "info": 0}
CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.9, "low": 0.7}
SOURCE_WEIGHT = {
    "safe_browsing": 1.0,
    "virustotal": 1.0,
    "ssrf_guard": 1.0,
    "mobsf": 0.9,
    "dynamic_analysis": 0.9,
    "browser_inspection": 0.9,
    "static_analysis_rules": 0.9,
    "static_analysis": 0.8,
    "http_inspection": 0.75,
    "rdap_inspection": 0.75,
    "dns_inspection": 0.7,
    "tls_inspection": 0.8,
    "brand_guard": 0.75,
    "phone_reports": 0.7,
    "integrity": 0.6,
    "url_heuristic": 0.6,
    "heuristic": 0.5,
    "llm_analysis": 0.45,
    "llm_vision": 0.45,
    "brand_agent": 0.6,
    "behavior_agent": 0.6,
    "phone_validation": 0.4,
}
POSITIVE_CHECKS = {
    "safe_browsing", "virustotal", "browser_inspection", "virustotal_hash_lookup",
    "apk_static_analysis", "ocr", "phone_reports", "mobsf", "dynamic_analysis",
}
LEVEL_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
CLEAN_EVIDENCE_MIN_CHECKS = 3


class RiskEngine:
    """Final risk assessment component.

    Calibrated scoring model that separates finding severity from overall URL classification.
    Deterministic: no LLM input. Coverage-aware: weak sources capped when checks < threshold.
    
    Usage:
        engine = RiskEngine()
        report = engine.assess(scan_id, scan_type, findings, checks_run, checks_unavailable)
    """

    def __init__(self):
        self.severity_weights = SEVERITY_WEIGHT
        self.confidence_weights = CONFIDENCE_WEIGHT
        self.source_weights = SOURCE_WEIGHT
        self.confirmed_sources = CONFIRMED_SOURCES
        self.positive_checks = POSITIVE_CHECKS
        self.clean_evidence_min_checks = CLEAN_EVIDENCE_MIN_CHECKS

    def assess(
        self,
        scan_id: str,
        scan_type: str,
        findings: list[Finding],
        checks_run: list[str],
        checks_unavailable: list[str],
        llm_usage: dict[str, Any] | None = None,
        limitations: list[str] | None = None,
        artifacts: dict[str, Any] | None = None,
        confidence: str | None = None,
    ) -> ScanReport:
        """Produce final scan report from findings and coverage.
        
        Separates finding.severity (individual threat level) from 
        scan.risk.level (overall URL classification).
        """
        return assess(
            scan_id, scan_type, findings, checks_run, checks_unavailable,
            llm_usage, limitations, artifacts, confidence
        )

    def fail_report(
        self,
        scan_id: str,
        scan_type: str,
        code: str,
        message: str,
        checks_run: list[str] | None = None,
        checks_unavailable: list[str] | None = None,
        limitations: list[str] | None = None,
    ) -> ScanReport:
        """Build scan_failed report when scanner cannot complete."""
        return fail_report(scan_id, scan_type, code, message, checks_run, checks_unavailable, limitations)


def positive_check_count(checks_run: list[str]) -> int:
    return sum(1 for name in checks_run if name in POSITIVE_CHECKS)


def calibrated_score(findings: list[Finding], checks_run: list[str]) -> int:
    residual = 1.0
    for item in findings:
        weight = SEVERITY_WEIGHT.get(item.severity, 0) / 100
        weight *= SOURCE_WEIGHT.get(item.source, 0.6)
        weight *= CONFIDENCE_WEIGHT.get(item.confidence, 0.85)
        residual *= max(0.0, 1.0 - min(weight, 0.95))
    score = round(100 * (1.0 - residual))
    if positive_check_count(checks_run) < 2:
        # One weak source is not enough to justify a high score.
        score = min(score, 60)
    return max(0, min(score, 100))


def score_level(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "unknown"


def _rank(level: str) -> int:
    return LEVEL_RANK.get(level, 0)


def assess(
    scan_id: str,
    scan_type: str,
    findings: list[Finding],
    checks_run: list[str],
    checks_unavailable: list[str],
    llm_usage: dict[str, Any] | None = None,
    limitations: list[str] | None = None,
    artifacts: dict[str, Any] | None = None,
    confidence: str | None = None,
) -> ScanReport:
    high = any(f.severity in ("high", "critical") and f.source in CONFIRMED_SOURCES for f in findings)
    high_risk = any(f.severity in ("high", "critical") for f in findings)
    medium = any(f.severity in ("medium", "high", "critical") for f in findings)
    if high:
        outcome, level = "confirmed_threat", "high"
        actions = ["Jangan buka tautan atau berikan informasi sensitif.", "Laporkan dan blokir pengirim."]
    elif high_risk:
        outcome, level = "suspicious", "high"
        actions = ["Jangan masukkan kredensial; verifikasi lewat kanal resmi."]
    elif medium:
        outcome, level = "suspicious", "medium"
        actions = ["Verifikasi melalui kanal resmi sebelum bertindak."]
    elif findings and checks_run:
        outcome, level = "insufficient_evidence", "unknown"
        actions = ["Kumpulkan bukti tambahan sebelum mempercayai konten ini."]
    else:
        outcome, level = "insufficient_evidence", "unknown"
        actions = ["Bukti belum cukup untuk menyimpulkan aman atau berbahaya."]

    score = calibrated_score(findings, checks_run)
    positives = positive_check_count(checks_run)
    target = score_level(score)
    if _rank(target) > _rank(level):
        level = target
    if level == "unknown" and not findings and positives >= CLEAN_EVIDENCE_MIN_CHECKS:
        level = "low"
    if level == "low" and not (not findings and positives >= CLEAN_EVIDENCE_MIN_CHECKS):
        # "low" needs positive evidence of safety, not merely an absence of findings.
        level = "unknown"
    if level == "low":
        # Enough independent checks ran clean; still not a guarantee, hence the wording.
        score = min(score, 8)
        actions = ["Tidak ditemukan indikator pada pemeriksaan yang berjalan, tetapi hasil ini bukan jaminan aman.", "Tetap verifikasi lewat kanal resmi sebelum mengirim data."]
    elif level == "high" and outcome == "insufficient_evidence":
        outcome, level = "suspicious", "high"
    elif level == "medium" and outcome == "insufficient_evidence":
        outcome = "suspicious"
    coverage_summary = f"{len(checks_run)} pemeriksaan berjalan; {len(checks_unavailable)} tidak tersedia."
    if positives < 2:
        coverage_summary += " Cakupan sumber independen masih tipis."
    
    # Build component status list
    components = []
    for check in checks_run:
        components.append(ComponentStatus(name=check, status="available"))
    for check in checks_unavailable:
        components.append(ComponentStatus(name=check, status="unavailable", reason="Service unavailable or timed out"))
    
    coverage = Coverage(
        checks_run=checks_run,
        checks_unavailable=checks_unavailable,
        components=components,
        summary=coverage_summary,
        positive_checks=positives,
        total_checks_attempted=len(checks_run) + len(checks_unavailable)
    )
    
    return ScanReport(
        scan_id=scan_id, type=scan_type, outcome=outcome,
        risk={"level": level, "score": score, "confidence": confidence or ("medium" if checks_run else "low"),
              "coverage": coverage.model_dump()},
        findings=findings, evidence_summary="; ".join(f.indicator for f in findings) or "Tidak ada indikator yang cukup untuk kesimpulan.",
        recommended_actions=actions, limitations=list(limitations or []),
        artifacts=artifacts or {"screenshot_path": None, "redirect_chain": []},
        llm_usage=llm_usage or {"model": "", "prompt_tokens": 0, "completion_tokens": 0, "latency_ms": 0, "status": "not_used"},
    )


def fail_report(
    scan_id: str,
    scan_type: str,
    code: str,
    message: str,
    checks_run: list[str] | None = None,
    checks_unavailable: list[str] | None = None,
    limitations: list[str] | None = None,
) -> ScanReport:
    """Build a scan_failed report so callers never have to invent an empty payload."""
    report = assess(
        scan_id,
        scan_type,
        [],
        list(checks_run or []),
        list(checks_unavailable or []),
        limitations=limitations,
    )
    report.outcome = "scan_failed"
    report.risk["level"] = "unknown"
    report.risk["score"] = None
    report.risk["confidence"] = "low"
    report.recommended_actions = ["Coba pindai ulang atau gunakan sumber lain untuk verifikasi."]
    report.evidence_summary = "Pemindaian tidak selesai."
    report.error = {"code": code, "message": message}
    return report


def finding(indicator: str, source: str, severity: str = "medium", metadata: dict[str, Any] | None = None, confidence: str = "medium") -> Finding:
    return Finding(id=f"{source}:{indicator}"[:64], indicator=indicator, source=source, severity=severity,
                   timestamp=datetime.now(timezone.utc).isoformat(), confidence=confidence, metadata=metadata or {})
