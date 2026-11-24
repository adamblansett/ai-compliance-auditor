"""Initial schema for AI Compliance & Regulatory Auditor.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "controls",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("control_code", sa.String(length=64), nullable=False),
        sa.Column("framework", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=120), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("scanner_domains_json", sa.JSON(), nullable=False),
        sa.Column("required_rules_json", sa.JSON(), nullable=False),
        sa.Column("owner_email", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("compliance_score", sa.Float(), nullable=False),
        sa.Column("evidence_summary", sa.Text(), nullable=False),
        sa.Column("remediation_guidance", sa.Text(), nullable=False),
        sa.Column("waiver_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_controls_control_code", "controls", ["control_code"], unique=True)
    op.create_index("ix_controls_framework", "controls", ["framework"], unique=False)
    op.create_index("ix_controls_status", "controls", ["status"], unique=False)

    op.create_table(
        "scan_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_name", sa.String(length=255), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("artifact_filename", sa.String(length=255), nullable=False),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("artifact_preview", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("total_checks", sa.Integer(), nullable=False),
        sa.Column("passed_checks", sa.Integer(), nullable=False),
        sa.Column("failed_checks", sa.Integer(), nullable=False),
        sa.Column("warning_checks", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("ai_summary", sa.Text(), nullable=False),
        sa.Column("llm_provider", sa.String(length=32), nullable=False),
        sa.Column("triggered_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_runs_target_type", "scan_runs", ["target_type"], unique=False)
    op.create_index("ix_scan_runs_artifact_sha256", "scan_runs", ["artifact_sha256"], unique=False)
    op.create_index("ix_scan_runs_status", "scan_runs", ["status"], unique=False)
    op.create_index("ix_scan_runs_created_at", "scan_runs", ["created_at"], unique=False)

    op.create_table(
        "control_evaluations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("control_id", sa.String(length=36), nullable=False),
        sa.Column("scan_run_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("passed_checks", sa.Integer(), nullable=False),
        sa.Column("failed_checks", sa.Integer(), nullable=False),
        sa.Column("warning_checks", sa.Integer(), nullable=False),
        sa.Column("findings_snapshot_json", sa.JSON(), nullable=False),
        sa.Column("ai_rationale", sa.Text(), nullable=False),
        sa.Column("llm_provider", sa.String(length=32), nullable=False),
        sa.Column("evaluated_by", sa.String(length=255), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["control_id"], ["controls.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_control_evaluations_control_id", "control_evaluations", ["control_id"], unique=False
    )
    op.create_index(
        "ix_control_evaluations_scan_run_id", "control_evaluations", ["scan_run_id"], unique=False
    )

    op.create_table(
        "scan_findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_run_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("domain", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("mapped_controls_json", sa.JSON(), nullable=False),
        sa.Column("evidence_snippet", sa.Text(), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_findings_scan_run_id", "scan_findings", ["scan_run_id"], unique=False)
    op.create_index("ix_scan_findings_rule_id", "scan_findings", ["rule_id"], unique=False)
    op.create_index("ix_scan_findings_domain", "scan_findings", ["domain"], unique=False)
    op.create_index("ix_scan_findings_severity", "scan_findings", ["severity"], unique=False)
    op.create_index("ix_scan_findings_status", "scan_findings", ["status"], unique=False)

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("sequence_no", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("actor_email", sa.String(length=255), nullable=False),
        sa.Column("actor_role", sa.String(length=64), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("details_json", sa.JSON(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_sequence_no", "audit_events", ["sequence_no"], unique=True)
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"], unique=False)
    op.create_index("ix_audit_events_entity_type", "audit_events", ["entity_type"], unique=False)
    op.create_index("ix_audit_events_entity_id", "audit_events", ["entity_id"], unique=False)
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"], unique=False)

    op.create_table(
        "approval_requests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("action_requested", sa.String(length=120), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("decided_by", sa.String(length=255), nullable=True),
        sa.Column("decision_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_approval_requests_entity_type", "approval_requests", ["entity_type"], unique=False
    )
    op.create_index(
        "ix_approval_requests_entity_id", "approval_requests", ["entity_id"], unique=False
    )
    op.create_index("ix_approval_requests_status", "approval_requests", ["status"], unique=False)

    op.create_table(
        "evidence_bundles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("bundle_name", sa.String(length=255), nullable=False),
        sa.Column("frameworks_json", sa.JSON(), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("period_end", sa.Date(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("chain_head_hash", sa.String(length=64), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("manifest_json", sa.JSON(), nullable=False),
        sa.Column("ai_attestation_summary", sa.Text(), nullable=False),
        sa.Column("compiled_by", sa.String(length=255), nullable=False),
        sa.Column("approval_id", sa.String(length=36), nullable=True),
        sa.Column("released_by", sa.String(length=255), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approval_id"], ["approval_requests.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_bundles_status", "evidence_bundles", ["status"], unique=False)

    op.create_table(
        "dsar_requests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("reference_code", sa.String(length=64), nullable=False),
        sa.Column("request_type", sa.String(length=32), nullable=False),
        sa.Column("regulation", sa.String(length=32), nullable=False),
        sa.Column("subject_email", sa.String(length=255), nullable=False),
        sa.Column("subject_identifier_hash", sa.String(length=64), nullable=False),
        sa.Column("data_systems_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=False),
        sa.Column("legal_hold_blocked", sa.Boolean(), nullable=False),
        sa.Column("blocking_hold_ids_json", sa.JSON(), nullable=False),
        sa.Column("export_package_sha256", sa.String(length=64), nullable=True),
        sa.Column("export_manifest_json", sa.JSON(), nullable=True),
        sa.Column("approval_id", sa.String(length=36), nullable=True),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approval_id"], ["approval_requests.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_dsar_requests_reference_code", "dsar_requests", ["reference_code"], unique=True
    )
    op.create_index(
        "ix_dsar_requests_request_type", "dsar_requests", ["request_type"], unique=False
    )
    op.create_index("ix_dsar_requests_regulation", "dsar_requests", ["regulation"], unique=False)
    op.create_index(
        "ix_dsar_requests_subject_email", "dsar_requests", ["subject_email"], unique=False
    )
    op.create_index(
        "ix_dsar_requests_subject_identifier_hash",
        "dsar_requests",
        ["subject_identifier_hash"],
        unique=False,
    )
    op.create_index("ix_dsar_requests_status", "dsar_requests", ["status"], unique=False)
    op.create_index("ix_dsar_requests_due_date", "dsar_requests", ["due_date"], unique=False)

    op.create_table(
        "legal_holds",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("hold_code", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("matter_reference", sa.String(length=120), nullable=False),
        sa.Column("custodian_scope_json", sa.JSON(), nullable=False),
        sa.Column("systems_scope_json", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("placed_by", sa.String(length=255), nullable=False),
        sa.Column("released_by", sa.String(length=255), nullable=True),
        sa.Column("placed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_legal_holds_hold_code", "legal_holds", ["hold_code"], unique=True)
    op.create_index("ix_legal_holds_status", "legal_holds", ["status"], unique=False)

    op.create_table(
        "retention_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("policy_code", sa.String(length=64), nullable=False),
        sa.Column("data_category", sa.String(length=120), nullable=False),
        sa.Column("framework", sa.String(length=32), nullable=False),
        sa.Column("system_name", sa.String(length=120), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False),
        sa.Column("actual_oldest_record_days", sa.Integer(), nullable=False),
        sa.Column("purge_mechanism", sa.String(length=255), nullable=False),
        sa.Column("encryption_at_rest", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_retention_policies_policy_code", "retention_policies", ["policy_code"], unique=True
    )
    op.create_index(
        "ix_retention_policies_framework", "retention_policies", ["framework"], unique=False
    )
    op.create_index(
        "ix_retention_policies_system_name", "retention_policies", ["system_name"], unique=False
    )
    op.create_index("ix_retention_policies_status", "retention_policies", ["status"], unique=False)

    op.create_table(
        "retention_exceptions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("policy_id", sa.String(length=36), nullable=False),
        sa.Column("requested_retention_days", sa.Integer(), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Date(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("approval_id", sa.String(length=36), nullable=True),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approval_id"], ["approval_requests.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["policy_id"], ["retention_policies.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_retention_exceptions_policy_id", "retention_exceptions", ["policy_id"], unique=False
    )
    op.create_index(
        "ix_retention_exceptions_status", "retention_exceptions", ["status"], unique=False
    )


def downgrade() -> None:
    op.drop_table("retention_exceptions")
    op.drop_table("retention_policies")
    op.drop_table("legal_holds")
    op.drop_table("dsar_requests")
    op.drop_table("evidence_bundles")
    op.drop_table("approval_requests")
    op.drop_table("audit_events")
    op.drop_table("scan_findings")
    op.drop_table("control_evaluations")
    op.drop_table("scan_runs")
    op.drop_table("controls")
