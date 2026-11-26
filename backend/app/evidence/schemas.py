from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.llm.pii import RedactionFinding


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sequence_no: int
    event_type: str
    actor_email: str
    actor_role: str
    entity_type: str
    entity_id: str
    action: str
    details_json: dict[str, Any]
    prev_hash: str
    event_hash: str
    created_at: datetime


class AuditChainVerifyOut(BaseModel):
    valid: bool
    total_events: int
    head_hash: str
    broken_sequence_no: int | None = None
    message: str


class ApprovalRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    entity_type: str
    entity_id: str
    action_requested: str
    summary: str
    risk_level: str
    payload_json: dict[str, Any]
    status: str
    requested_by: str
    decided_by: str | None = None
    decision_notes: str | None = None
    created_at: datetime
    decided_at: datetime | None = None


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    notes: str = Field(default="", max_length=1000)


def _default_frameworks() -> list[Literal["SOC2", "HIPAA", "GDPR"]]:
    return ["SOC2", "HIPAA", "GDPR"]


class BundleCompileRequest(BaseModel):
    bundle_name: str = Field(min_length=3, max_length=255)
    frameworks: list[Literal["SOC2", "HIPAA", "GDPR"]] = Field(
        default_factory=_default_frameworks
    )
    period_start: date | None = None
    period_end: date | None = None


class EvidenceBundleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    bundle_name: str
    frameworks_json: list[str]
    period_start: date
    period_end: date
    status: str
    item_count: int
    chain_head_hash: str
    manifest_sha256: str
    ai_attestation_summary: str
    compiled_by: str
    approval_id: str | None = None
    signature_alg: str | None = None
    signature_key_id: str | None = None
    signature_hex: str | None = None
    signed_at: datetime | None = None
    released_by: str | None = None
    released_at: datetime | None = None
    created_at: datetime


class EvidenceBundleDetailOut(EvidenceBundleOut):
    manifest_json: dict[str, Any]


class EvidenceBundleExportOut(BaseModel):
    bundle_id: str
    bundle_name: str
    status: str
    chain_head_hash: str
    manifest_sha256: str
    signature_alg: str | None = None
    signature_key_id: str | None = None
    signature_hex: str | None = None
    manifest: dict[str, Any]


class BundleVerifyOut(BaseModel):
    valid: bool
    item_count: int
    chain_head_hash: str
    manifest_sha256: str
    broken_item_seq: int | None = None
    errors: list[str] = Field(default_factory=list)
    message: str


class BundleVerifyPayloadRequest(BaseModel):
    manifest: dict[str, Any]
    expected_manifest_sha256: str | None = None
    expected_chain_head: str | None = None


class PiiRedactRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20000)


class PiiRedactResponse(BaseModel):
    redacted_text: str
    findings: list[RedactionFinding]
    total_redactions: int
