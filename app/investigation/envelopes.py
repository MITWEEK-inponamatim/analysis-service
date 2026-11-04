"""Schemas shared by skills, agents, planner, and the orchestrator."""
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
Status = Literal["completed", "partial", "failed", "skipped"]


class Observation(BaseModel):
    evidence_id: str
    fact: str
    kind: str
    observed: bool = True
    payload: dict[str, Any] = Field(default_factory=dict)


class InvestigationFinding(BaseModel):
    indicator: str
    severity: Severity
    confidence: Confidence = "medium"
    evidence_ids: list[str] = Field(default_factory=list)
    interpretation: str = ""


class SkillEnvelope(BaseModel):
    skill: str
    status: Status = "completed"
    evidence_ids: list[str] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    findings: list[InvestigationFinding] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    unavailable: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)
    tool_calls: int = 0
    tokens: int = 0

class AgentFinding(BaseModel):
    indicator: str = Field(max_length=500)
    severity: Severity
    confidence: Confidence = "medium"
    evidence_ids: list[str] = Field(default_factory=list)
    interpretation: str = Field(default="", max_length=800)


class AgentAnswer(BaseModel):
    findings: list[AgentFinding] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    summary: str = Field(default="", max_length=600)


class PlanStep(BaseModel):
    step: int
    agent: Literal["brand", "behavior"]
    skill: str
    reason: str
    expected_evidence: list[str] = Field(default_factory=list)
    depends_on: list[int] = Field(default_factory=list)
    params: dict[str, Any] = Field(default_factory=dict)


class PlanEnvelope(BaseModel):
    status: Literal["completed", "partial", "stopped"] = "completed"
    known_facts: list[dict[str, Any]] = Field(default_factory=list)
    open_questions: list[dict[str, Any]] = Field(default_factory=list)
    plan: list[PlanStep] = Field(default_factory=list)
    stop_reason: str | None = None
    budget: dict[str, Any] = Field(default_factory=dict)
