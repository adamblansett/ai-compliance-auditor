from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

TargetType = Literal["config", "encryption", "logging", "rbac", "sop", "full_suite"]


class ScanRequest(BaseModel):
    target_name: str = Field(min_length=2, max_length=255)
    target_type: TargetType = "full_suite"
    artifact_filename: str = Field(default="artifact.txt", min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=200000)
    auto_evaluate_controls: bool = True


class ScanFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_run_id: str
    rule_id: str
    domain: str
    severity: str
    status: str
    title: str
    detail: str
    remediation: str
    mapped_controls_json: list[str]
    evidence_snippet: str
    evidence_hash: str
    created_at: datetime


class ScanRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_name: str
    target_type: str
    artifact_filename: str
    artifact_sha256: str
    artifact_preview: str
    status: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    warning_checks: int
    risk_score: float
    ai_summary: str
    llm_provider: str
    triggered_by: str
    created_at: datetime


class ScanRunDetailOut(ScanRunOut):
    findings: list[ScanFindingOut] = Field(default_factory=list)


class ScannerPresetOut(BaseModel):
    preset_id: str
    label: str
    target_name: str
    target_type: TargetType
    artifact_filename: str
    description: str
    content: str
