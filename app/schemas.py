from typing import Any, Literal
from pydantic import BaseModel, Field

ScanType = Literal["url", "message", "phone", "image", "application"]
PhoneRegion = Literal["ID", "MY", "SG", "US", "GB"]
ReportStatus = Literal["pending", "verified", "rejected", "rejected_spam"]

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
