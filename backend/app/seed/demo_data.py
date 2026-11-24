from datetime import date, timedelta

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.controls.evaluator import (
    ensure_default_controls,
    evaluate_all_controls,
    request_control_waiver,
)
from app.core.auth import Actor
from app.core.config import Settings
from app.db.models import (
    ApprovalRequest,
    AuditEvent,
    Control,
    ControlEvaluation,
    DsarRequest,
    EvidenceBundle,
    LegalHold,
    RetentionException,
    RetentionPolicy,
    ScanFinding,
    ScanRun,
)
from app.evidence.compiler import compile_evidence_bundle
from app.llm.router import LLMRouter
from app.privacy.schemas import (
    DsarCreateRequest,
    LegalHoldCreateRequest,
    RetentionExceptionCreateRequest,
    RetentionPolicyCreateRequest,
)
from app.privacy.service import (
    create_dsar,
    create_legal_hold,
    create_retention_policy,
    prepare_dsar_fulfillment,
    request_retention_exception,
    verify_retention_policies,
)
from app.scanners.collectors import SCANNER_PRESETS
from app.scanners.engine import execute_scan


class SeedSummaryOut(BaseModel):
    seeded: bool
    controls_count: int
    scan_runs_count: int
    evidence_bundles_count: int
    dsars_count: int
    legal_holds_count: int
    retention_policies_count: int
    pending_approvals_count: int
    message: str


async def _clear_all_tables(db: AsyncSession) -> None:
    for model in (
        ControlEvaluation,
        ScanFinding,
        ScanRun,
        EvidenceBundle,
        RetentionException,
        RetentionPolicy,
        DsarRequest,
        LegalHold,
        ApprovalRequest,
        AuditEvent,
        Control,
    ):
        await db.execute(delete(model))
    await db.commit()


async def seed_demo_dataset(
    db: AsyncSession,
    *,
    llm_router: LLMRouter,
    settings: Settings,
    actor: Actor,
    reset: bool = False,
) -> SeedSummaryOut:
    """Populate a realistic, internally consistent compliance audit dataset."""
    if reset:
        await _clear_all_tables(db)

    existing_controls = (await db.execute(select(Control.id))).scalars().all()
    if existing_controls and not reset:
        scan_cnt = len((await db.execute(select(ScanRun.id))).scalars().all())
        bundle_cnt = len((await db.execute(select(EvidenceBundle.id))).scalars().all())
        dsar_cnt = len((await db.execute(select(DsarRequest.id))).scalars().all())
        hold_cnt = len((await db.execute(select(LegalHold.id))).scalars().all())
        pol_cnt = len((await db.execute(select(RetentionPolicy.id))).scalars().all())
        app_cnt = len(
            (
                await db.execute(
                    select(ApprovalRequest.id).where(ApprovalRequest.status == "pending")
                )
            )
            .scalars()
            .all()
        )
        return SeedSummaryOut(
            seeded=False,
            controls_count=len(existing_controls),
            scan_runs_count=scan_cnt,
            evidence_bundles_count=bundle_cnt,
            dsars_count=dsar_cnt,
            legal_holds_count=hold_cnt,
            retention_policies_count=pol_cnt,
            pending_approvals_count=app_cnt,
            message="Demo dataset already exists (pass reset=true to rebuild).",
        )

    _, controls_count = await ensure_default_controls(db)
    await db.commit()

    await create_legal_hold(
        db,
        payload=LegalHoldCreateRequest(
            hold_code="LH-2026-001",
            title="Acme Customer Billing & Contract Dispute Hold",
            matter_reference="MATTER-2026-409",
            custodian_scope=["alex.morgan@example.com"],
            systems_scope=["billing_ledger", "crm_postgres"],
            reason="Active commercial arbitration preservation order; suspend erasure and purges.",
        ),
        actor=actor,
    )

    pol_specs = (
        RetentionPolicyCreateRequest(
            policy_code="RET-001",
            data_category="Security & Access Audit Logs",
            framework="SOC2",
            system_name="siem_archive",
            retention_days=365,
            actual_oldest_record_days=180,
            purge_mechanism="Immutable S3 Object Lock lifecycle expiry",
            encryption_at_rest=True,
        ),
        RetentionPolicyCreateRequest(
            policy_code="RET-002",
            data_category="Staging Session Telemetry",
            framework="GDPR",
            system_name="analytics_warehouse",
            retention_days=90,
            actual_oldest_record_days=142,
            purge_mechanism="Nightly SQL partition drop job",
            encryption_at_rest=True,
        ),
        RetentionPolicyCreateRequest(
            policy_code="RET-003",
            data_category="Billing Ledger & Dispute Snapshots",
            framework="SOC2",
            system_name="billing_ledger",
            retention_days=365,
            actual_oldest_record_days=410,
            purge_mechanism="Automated archival purge",
            encryption_at_rest=True,
        ),
        RetentionPolicyCreateRequest(
            policy_code="RET-004",
            data_category="Patient Authorization & Consent Records",
            framework="HIPAA",
            system_name="ehr_vault",
            retention_days=2190,
            actual_oldest_record_days=920,
            purge_mechanism="KMS crypto-shredding scheduler",
            encryption_at_rest=True,
        ),
    )
    created_policies: list[RetentionPolicy] = []
    for pol_req in pol_specs:
        created_policies.append(await create_retention_policy(db, payload=pol_req, actor=actor))

    await verify_retention_policies(db, actor=actor)

    ret_002 = next(p for p in created_policies if p.policy_code == "RET-002")
    await request_retention_exception(
        db,
        policy_id=ret_002.id,
        payload=RetentionExceptionCreateRequest(
            requested_retention_days=180,
            justification=(
                "Temporary 180-day retention extension while analytics backfill "
                "validation completes."
            ),
            expires_at=date.today() + timedelta(days=60),
        ),
        actor=actor,
    )

    # Create 3 DSARs (erasure blocked by LH-2026-001, portability queued for HITL, access open)
    await create_dsar(
        db,
        payload=DsarCreateRequest(
            request_type="erasure",
            regulation="GDPR",
            subject_email="alex.morgan@example.com",
            data_systems=["billing_ledger", "crm_postgres"],
            notes="Article 17 erasure request from former enterprise billing contact.",
        ),
        settings=settings,
        actor=actor,
    )
    portability_dsar = await create_dsar(
        db,
        payload=DsarCreateRequest(
            request_type="portability",
            regulation="GDPR",
            subject_email="maya.patel@example.com",
            data_systems=["crm_postgres", "analytics_warehouse"],
            notes="Article 20 machine-readable export requested.",
        ),
        settings=settings,
        actor=actor,
    )
    await prepare_dsar_fulfillment(
        db,
        dsar_id=portability_dsar.id,
        llm_router=llm_router,
        actor=actor,
    )
    await create_dsar(
        db,
        payload=DsarCreateRequest(
            request_type="access",
            regulation="CCPA",
            subject_email="jordan.lee@example.com",
            data_systems=["crm_postgres", "ehr_vault"],
            notes="Right to know disclosure request in intake review.",
        ),
        settings=settings,
        actor=actor,
    )

    for preset in SCANNER_PRESETS:
        await execute_scan(
            db,
            target_name=preset.target_name,
            target_type=preset.target_type,
            artifact_filename=preset.artifact_filename,
            raw_bytes=preset.content.encode("utf-8"),
            content=preset.content,
            auto_evaluate_controls=False,
            llm_router=llm_router,
            actor=actor,
        )

    evaluated = await evaluate_all_controls(
        db,
        framework=None,
        llm_router=llm_router,
        actor=actor,
    )

    soc2_cc66 = next((c for c in evaluated if c.control_code == "SOC2-CC6.6"), None)
    if soc2_cc66 is not None:
        await request_control_waiver(
            db,
            control_id=soc2_cc66.id,
            justification=(
                "Staging API environment isolated behind corporate VPN while wildcard CORS "
                "remediation PR rolls out."
            ),
            waiver_days=14,
            actor=actor,
        )

    await compile_evidence_bundle(
        db,
        bundle_name="Q4 2026 Multi-Framework Readiness Package",
        frameworks=["SOC2", "HIPAA", "GDPR"],
        period_start=date.today() - timedelta(days=30),
        period_end=date.today(),
        llm_router=llm_router,
        actor=actor,
    )

    app_cnt = len(
        (
            await db.execute(
                select(ApprovalRequest.id).where(ApprovalRequest.status == "pending")
            )
        )
        .scalars()
        .all()
    )
    return SeedSummaryOut(
        seeded=True,
        controls_count=controls_count,
        scan_runs_count=len(SCANNER_PRESETS),
        evidence_bundles_count=1,
        dsars_count=3,
        legal_holds_count=1,
        retention_policies_count=len(pol_specs),
        pending_approvals_count=app_cnt,
        message=(
            "Seeded SOC 2 / HIPAA / GDPR controls, 5 compliance scans, 3 DSARs, 1 legal hold, "
            "4 retention policies, 1 hash-chained bundle, and 4 HITL approval gates."
        ),
    )
