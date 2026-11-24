from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class DsarCreateRequest(BaseModel):
    request_type: Literal["access", "erasure", "rectification", "portability", "restriction"]
    regulation: Literal["GDPR", "CCPA", "HIPAA"] = "GDPR"
    subject_email: str = Field(min_length=3, max_length=255)
    data_systems: list[str] = Field(
        default_factory=lambda: ["crm_postgres", "analytics_warehouse", "object_storage"]
    )
    due_date: date | None = None
    notes: str = Field(default="", max_length=2000)


class DsarRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    reference_code: str
    request_type: str
    regulation: str
    subject_email: str
    subject_identifier_hash: str
    data_systems_json: list[str]
    status: str
    due_date: date
    legal_hold_blocked: bool
    blocking_hold_ids_json: list[str]
    export_package_sha256: str | None = None
    export_manifest_json: dict[str, Any] | None = None
    approval_id: str | None = None
    notes: str
    created_by: str
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class LegalHoldCreateRequest(BaseModel):
    hold_code: str | None = Field(default=None, max_length=64)
    title: str = Field(min_length=3, max_length=255)
    matter_reference: str = Field(min_length=2, max_length=120)
    custodian_scope: list[str] = Field(default_factory=list)
    systems_scope: list[str] = Field(default_factory=list)
    reason: str = Field(min_length=3, max_length=2000)


class LegalHoldReleaseRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)


class LegalHoldOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    hold_code: str
    title: str
    matter_reference: str
    custodian_scope_json: list[str]
    systems_scope_json: list[str]
    reason: str
    status: str
    placed_by: str
    released_by: str | None = None
    placed_at: datetime
    released_at: datetime | None = None


class RetentionPolicyCreateRequest(BaseModel):
    policy_code: str = Field(min_length=2, max_length=64)
    data_category: str = Field(min_length=2, max_length=120)
    framework: Literal["SOC2", "HIPAA", "GDPR"] = "GDPR"
    system_name: str = Field(min_length=2, max_length=120)
    retention_days: int = Field(ge=1, le=36500)
    actual_oldest_record_days: int = Field(ge=0, le=36500)
    purge_mechanism: str = Field(min_length=2, max_length=255)
    encryption_at_rest: bool = True


class RetentionPolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    policy_code: str
    data_category: str
    framework: str
    system_name: str
    retention_days: int
    actual_oldest_record_days: int
    purge_mechanism: str
    encryption_at_rest: bool
    status: str
    last_verified_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class RetentionExceptionCreateRequest(BaseModel):
    requested_retention_days: int = Field(ge=1, le=36500)
    justification: str = Field(min_length=5, max_length=2000)
    expires_at: date


class RetentionExceptionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    policy_id: str
    requested_retention_days: int
    justification: str
    expires_at: date
    status: str
    approval_id: str | None = None
    requested_by: str
    approved_by: str | None = None
    created_at: datetime
    updated_at: datetime
