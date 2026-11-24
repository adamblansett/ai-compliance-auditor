from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ControlCreateRequest(BaseModel):
    control_code: str = Field(min_length=3, max_length=64)
    framework: Literal["SOC2", "HIPAA", "GDPR"]
    category: str = Field(min_length=2, max_length=120)
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(min_length=5, max_length=2000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    scanner_domains: list[str] = Field(default_factory=list)
    required_rules: list[str] = Field(default_factory=list)
    owner_email: str = Field(min_length=3, max_length=255)
    remediation_guidance: str = Field(default="", max_length=2000)


class ControlOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    control_code: str
    framework: str
    category: str
    title: str
    description: str
    severity: str
    scanner_domains_json: list[str]
    required_rules_json: list[str]
    owner_email: str
    status: str
    compliance_score: float
    evidence_summary: str
    remediation_guidance: str
    waiver_expires_at: datetime | None = None
    last_evaluated_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class ControlEvaluationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    control_id: str
    scan_run_id: str | None = None
    status: str
    score: float
    passed_checks: int
    failed_checks: int
    warning_checks: int
    findings_snapshot_json: list[dict[str, Any]]
    ai_rationale: str
    llm_provider: str
    evaluated_by: str
    evaluated_at: datetime


class WaiverCreateRequest(BaseModel):
    justification: str = Field(min_length=5, max_length=2000)
    waiver_days: int = Field(default=30, ge=1, le=365)


class WaiverApprovalOut(BaseModel):
    control_id: str
    control_code: str
    approval_id: str
    status: str
    message: str


class FrameworkPostureOut(BaseModel):
    framework: str
    total_controls: int
    passing: int
    failing: int
    warning: int
    waived: int
    not_evaluated: int
    score_pct: float


class PostureSummaryOut(BaseModel):
    overall_score_pct: float
    total_controls: int
    frameworks: list[FrameworkPostureOut]
