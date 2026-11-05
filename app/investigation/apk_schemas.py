"""Validated model output schemas for APK investigation agents."""

from typing import Literal

from pydantic import BaseModel, Field


class APKFinding(BaseModel):
    """A concise, evidence-linked APK behavior or obfuscation finding."""

    indicator: str = Field(min_length=1, max_length=500)
    severity: Literal["info", "low", "medium", "high"]
    confidence: Literal["low", "medium", "high"] = "medium"
    class_name: str | None = Field(default=None, max_length=300)
    method_name: str | None = Field(default=None, max_length=200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    extracted_data: list[str] = Field(default_factory=list, max_length=20)


class BehaviorAgentOutput(BaseModel):
    findings: list[APKFinding] = Field(default_factory=list, max_length=50)
    summary: str = Field(default="", max_length=1000)
    tool_calls_needed: int = Field(default=0, ge=0, le=6)


class ObfuscationAgentOutput(BaseModel):
    findings: list[APKFinding] = Field(default_factory=list, max_length=50)
    obfuscation_level: Literal["none", "light", "moderate", "heavy"] = "none"
    summary: str = Field(default="", max_length=1000)
    tool_calls_needed: int = Field(default=0, ge=0, le=6)
