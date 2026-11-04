from typing import Any, Literal
from pydantic import BaseModel, Field

ScanType = Literal["url", "phone", "application"]
# Detection scope is Indonesian numbers only; +62 is enforced from the parsed country code,
# not from this field, so "+1..." submitted with region ID is still rejected.
PhoneRegion = Literal["ID"]
ReportStatus = Literal["pending", "verified", "rejected", "rejected_spam"]

class ComponentStatus(BaseModel):
    """Component availability status for scan coverage tracking."""
    name: str
    status: Literal["available", "unavailable", "partial", "not_attempted"]
    reason: str | None = None

class Coverage(BaseModel):
    """Scan coverage and component availability metrics."""
    checks_run: list[str]
    checks_unavailable: list[str]
    components: list[ComponentStatus] = Field(default_factory=list)
    summary: str
    positive_checks: int = 0
    total_checks_attempted: int = 0

class ScanMetrics(BaseModel):
    """Metrics for manual evaluation of scanner performance."""
    scan_id: str
    timestamp: str
    duration_ms: int
    components_used: list[str]
    llm_calls: int = 0
    llm_tokens: int = 0
    llm_cost_usd: float = 0.0
    external_api_calls: int = 0
    findings_count: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_source: dict[str, int] = Field(default_factory=dict)
    final_risk_level: str
    outcome: str
    # For precision/recall evaluation (manual ground truth labeling)
    ground_truth_label: str | None = None  # "malicious" | "benign" | "unknown"
    evaluation_notes: str | None = None

class JobRequest(BaseModel):
    scan_id: str
    user_id: str
    type: ScanType
    input: dict[str, Any]
    options: dict[str, Any] = Field(default_factory=dict)

class PhoneNormalizeRequest(BaseModel):
    """Shared normalisation contract: the Go API stores only the E.164 form it returns."""

    number: str = Field(min_length=4, max_length=32)
    default_region: PhoneRegion = "ID"

class PhoneReportModerationRequest(BaseModel):
    status: ReportStatus


class PhoneEvidenceRequest(BaseModel):
    """One evidence image for a community report, handed over by Go as base64.

    Multipart would need a new dependency here; Go already holds the bytes and caps the size,
    so the body stays JSON and only this module talks to Cloudinary.
    """

    user_id: str = Field(min_length=36, max_length=36)
    reference: str = Field(min_length=8, max_length=64)
    mime: str = Field(min_length=4, max_length=64)
    data_base64: str = Field(min_length=1, max_length=7_000_000)


class PhoneEvidenceDeleteRequest(BaseModel):
    public_id: str = Field(min_length=1, max_length=512)

class Finding(BaseModel):
    id: str
    indicator: str
    source: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    timestamp: str
    confidence: Literal["low", "medium", "high"]
    metadata: dict[str, Any] = Field(default_factory=dict)
    limitations: str = ""

class ScanReport(BaseModel):
    scan_id: str
    type: ScanType
    outcome: Literal["confirmed_threat", "suspicious", "insufficient_evidence", "scan_failed"]
    risk: dict[str, Any]
    findings: list[Finding]
    evidence_summary: str
    recommended_actions: list[str]
    limitations: list[str]
    artifacts: dict[str, Any]
    llm_usage: dict[str, Any]
    error: dict[str, str] | None = None
