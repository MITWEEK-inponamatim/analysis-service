"""Pydantic schemas for APK investigation agent structured output."""

from typing import Literal
from pydantic import BaseModel, Field


class APKFinding(BaseModel):
    """Single finding from APK investigation agent."""
    
    indicator: str = Field(
        description="Concise finding description (50-150 chars). Example: 'SMS forwarding to +1234567890 via MainActivity.sendSMS()'"
    )
    
    severity: Literal["info", "low", "medium", "high"] = Field(
        description="Severity level. Use 'medium' for confirmed suspicious behavior, 'high' for clear malicious behavior with concrete evidence."
    )
    
    class_name: str | None = Field(
        default=None,
        description="Decompiled class name where behavior found (e.g., 'com.example.MainActivity')"
    )
    
    method_name: str | None = Field(
        default=None,
        description="Method name where behavior occurs (e.g., 'onCreate', 'sendData')"
    )
    
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Evidence IDs from store that support this finding"
    )
    
    extracted_data: list[str] = Field(
        default_factory=list,
        description="Concrete extracted data: URLs, phone numbers, IP addresses, package names"
    )


class BehaviorAgentOutput(BaseModel):
    """Structured output from behavior agent."""
    
    findings: list[APKFinding] = Field(
        default_factory=list,
        description="Concrete malicious behaviors found with evidence"
    )
    
    summary: str = Field(
        description="1-2 sentence summary of APK behavior analysis"
    )
    
    tool_calls_needed: int = Field(
        description="Number of tool calls used to investigate"
    )


class ObfuscationAgentOutput(BaseModel):
    """Structured output from obfuscation agent."""
    
    findings: list[APKFinding] = Field(
        default_factory=list,
        description="Obfuscation techniques linked to malicious intent"
    )
    
    obfuscation_level: Literal["none", "light", "moderate", "heavy"] = Field(
        description="Overall obfuscation assessment. 'heavy' = DexGuard/custom packer, 'moderate' = R8/ProGuard, 'light' = basic renaming, 'none' = readable code"
    )
    
    summary: str = Field(
        description="1-2 sentence summary of obfuscation analysis and intent"
    )
    
    tool_calls_needed: int = Field(
        description="Number of tool calls used to investigate"
    )
