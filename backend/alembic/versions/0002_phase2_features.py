"""Phase 2 features: users, bundle signatures, scheduled scans, Policy RAG, and drift alerts.

Revision ID: 0002_phase2_features
Revises: 0001_initial_schema
Create Date: 2026-11-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_phase2_features"
down_revision: str | Sequence[str] | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("evidence_bundles") as batch_op:
        batch_op.add_column(sa.Column("signature_alg", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("signature_key_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("signature_hex", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "scheduled_scans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("scan_mode", sa.String(length=32), nullable=False),
        sa.Column("target_ref", sa.String(length=500), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_run_id", sa.String(length=36), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["last_scan_run_id"], ["scan_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scheduled_scans_is_active", "scheduled_scans", ["is_active"], unique=False)

    op.create_table(
        "policy_documents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("framework", sa.String(length=32), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("document_sha256", sa.String(length=64), nullable=False),
        sa.Column("pii_redaction_count", sa.Integer(), nullable=False),
        sa.Column("chunk_count", sa.Integer(), nullable=False),
        sa.Column("uploaded_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policy_documents_framework", "policy_documents", ["framework"], unique=False)
    op.create_index(
        "ix_policy_documents_document_sha256",
        "policy_documents",
        ["document_sha256"],
        unique=False,
    )

    op.create_table(
        "policy_chunks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("document_id", sa.String(length=36), nullable=False),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("section_heading", sa.String(length=255), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("embedding_json", sa.JSON(), nullable=False),
        sa.Column("mapped_controls_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["document_id"], ["policy_documents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policy_chunks_document_id", "policy_chunks", ["document_id"], unique=False)

    op.create_table(
        "alert_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("alert_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("dispatched_webhooks_count", sa.Integer(), nullable=False),
        sa.Column("acknowledged_by", sa.String(length=255), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_events_alert_type", "alert_events", ["alert_type"], unique=False)
    op.create_index("ix_alert_events_severity", "alert_events", ["severity"], unique=False)
    op.create_index("ix_alert_events_entity_id", "alert_events", ["entity_id"], unique=False)
    op.create_index("ix_alert_events_status", "alert_events", ["status"], unique=False)
    op.create_index("ix_alert_events_created_at", "alert_events", ["created_at"], unique=False)

    op.create_table(
        "alert_webhooks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("target_url", sa.String(length=500), nullable=False),
        sa.Column("event_types_json", sa.JSON(), nullable=False),
        sa.Column("secret_hmac", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("last_delivery_status", sa.String(length=120), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_webhooks_is_active", "alert_webhooks", ["is_active"], unique=False)


def downgrade() -> None:
    op.drop_table("alert_webhooks")
    op.drop_table("alert_events")
    op.drop_table("policy_chunks")
    op.drop_table("policy_documents")
    op.drop_table("scheduled_scans")
    op.drop_table("users")

    with op.batch_alter_table("evidence_bundles") as batch_op:
        batch_op.drop_column("signed_at")
        batch_op.drop_column("signature_hex")
        batch_op.drop_column("signature_key_id")
        batch_op.drop_column("signature_alg")
