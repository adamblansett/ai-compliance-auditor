from datetime import date, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, new_uuid, utcnow


class Control(Base):
    """Declarative SOC 2, HIPAA, or GDPR compliance control requirement."""

    __tablename__ = "controls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    control_code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    framework: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(120))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    scanner_domains_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    required_rules_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    owner_email: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="not_evaluated", index=True)
    compliance_score: Mapped[float] = mapped_column(Float, default=0.0)
    evidence_summary: Mapped[str] = mapped_column(Text, default="")
    remediation_guidance: Mapped[str] = mapped_column(Text, default="")
    waiver_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ScanRun(Base):
    """Executed policy/configuration/encryption/logging/RBAC/SOP scan run."""

    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    target_name: Mapped[str] = mapped_column(String(255))
    target_type: Mapped[str] = mapped_column(String(32), index=True)
    artifact_filename: Mapped[str] = mapped_column(String(255))
    artifact_sha256: Mapped[str] = mapped_column(String(64), index=True)
    artifact_preview: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="passed", index=True)
    total_checks: Mapped[int] = mapped_column(Integer, default=0)
    passed_checks: Mapped[int] = mapped_column(Integer, default=0)
    failed_checks: Mapped[int] = mapped_column(Integer, default=0)
    warning_checks: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    ai_summary: Mapped[str] = mapped_column(Text, default="")
    llm_provider: Mapped[str] = mapped_column(String(32), default="mock")
    triggered_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class ControlEvaluation(Base):
    """Point-in-time evaluation result for a single compliance control."""

    __tablename__ = "control_evaluations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    control_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("controls.id", ondelete="CASCADE"), index=True
    )
    scan_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(String(32))
    score: Mapped[float] = mapped_column(Float, default=0.0)
    passed_checks: Mapped[int] = mapped_column(Integer, default=0)
    failed_checks: Mapped[int] = mapped_column(Integer, default=0)
    warning_checks: Mapped[int] = mapped_column(Integer, default=0)
    findings_snapshot_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    ai_rationale: Mapped[str] = mapped_column(Text, default="")
    llm_provider: Mapped[str] = mapped_column(String(32), default="mock")
    evaluated_by: Mapped[str] = mapped_column(String(255))
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanFinding(Base):
    """Individual rule check result produced by a compliance scanner."""

    __tablename__ = "scan_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    domain: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text, default="")
    mapped_controls_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence_snippet: Mapped[str] = mapped_column(Text, default="")
    evidence_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    """Immutable SHA-256 hash-chained compliance audit trail entry."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    sequence_no: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    actor_email: Mapped[str] = mapped_column(String(255))
    actor_role: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    entity_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64))
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class ApprovalRequest(Base):
    """Human-in-the-loop governance gate for high-impact compliance decisions."""

    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    entity_id: Mapped[str] = mapped_column(String(64), index=True)
    action_requested: Mapped[str] = mapped_column(String(120))
    summary: Mapped[str] = mapped_column(Text)
    risk_level: Mapped[str] = mapped_column(String(32), default="medium")
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    requested_by: Mapped[str] = mapped_column(String(255))
    decided_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EvidenceBundle(Base):
    """Tamper-evident hash-chained audit package compiled for external auditors."""

    __tablename__ = "evidence_bundles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    bundle_name: Mapped[str] = mapped_column(String(255))
    frameworks_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(32), default="pending_approval", index=True)
    item_count: Mapped[int] = mapped_column(Integer, default=0)
    chain_head_hash: Mapped[str] = mapped_column(String(64))
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    manifest_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ai_attestation_summary: Mapped[str] = mapped_column(Text, default="")
    compiled_by: Mapped[str] = mapped_column(String(255))
    approval_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("approval_requests.id", ondelete="SET NULL"), nullable=True
    )
    released_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DsarRequest(Base):
    """Data Subject Access Request (DSAR) workflow with SLA and legal-hold checks."""

    __tablename__ = "dsar_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    reference_code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    request_type: Mapped[str] = mapped_column(String(32), index=True)
    regulation: Mapped[str] = mapped_column(String(32), index=True)
    subject_email: Mapped[str] = mapped_column(String(255), index=True)
    subject_identifier_hash: Mapped[str] = mapped_column(String(64), index=True)
    data_systems_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="received", index=True)
    due_date: Mapped[date] = mapped_column(Date, index=True)
    legal_hold_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    blocking_hold_ids_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    export_package_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    export_manifest_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    approval_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("approval_requests.id", ondelete="SET NULL"), nullable=True
    )
    notes: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(255))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class LegalHold(Base):
    """Litigation or regulatory legal hold blocking destructive erasure or purges."""

    __tablename__ = "legal_holds"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    hold_code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    matter_reference: Mapped[str] = mapped_column(String(120))
    custodian_scope_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    systems_scope_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    placed_by: Mapped[str] = mapped_column(String(255))
    released_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    placed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RetentionPolicy(Base):
    """Data retention schedule verified against actual record ages and legal holds."""

    __tablename__ = "retention_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    policy_code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    data_category: Mapped[str] = mapped_column(String(120))
    framework: Mapped[str] = mapped_column(String(32), index=True)
    system_name: Mapped[str] = mapped_column(String(120), index=True)
    retention_days: Mapped[int] = mapped_column(Integer)
    actual_oldest_record_days: Mapped[int] = mapped_column(Integer)
    purge_mechanism: Mapped[str] = mapped_column(String(255))
    encryption_at_rest: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(32), default="compliant", index=True)
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class RetentionException(Base):
    """Time-bounded retention extension exception subject to HITL approval."""

    __tablename__ = "retention_exceptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    policy_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("retention_policies.id", ondelete="CASCADE"), index=True
    )
    requested_retention_days: Mapped[int] = mapped_column(Integer)
    justification: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[date] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(32), default="pending_approval", index=True)
    approval_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("approval_requests.id", ondelete="SET NULL"), nullable=True
    )
    requested_by: Mapped[str] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
