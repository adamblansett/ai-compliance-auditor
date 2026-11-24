from datetime import date

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.controls.evaluator import get_posture_summary
from app.controls.schemas import PostureSummaryOut
from app.core.auth import Actor, get_current_actor
from app.db.models import (
    ApprovalRequest,
    DsarRequest,
    EvidenceBundle,
    LegalHold,
    RetentionPolicy,
    ScanFinding,
    ScanRun,
)
from app.db.session import get_db
from app.evidence.chain import verify_audit_chain
from app.evidence.schemas import AuditChainVerifyOut

router = APIRouter(prefix="/overview", tags=["overview"])


class DsarMetricsOut(BaseModel):
    total: int
    open: int
    overdue: int
    legal_hold_blocked: int
    completed: int


class RetentionMetricsOut(BaseModel):
    total: int
    compliant: int
    violations: int
    suspended: int
    exception_granted: int


class OverviewSummaryOut(BaseModel):
    posture: PostureSummaryOut
    open_findings_by_severity: dict[str, int]
    scan_runs_count: int
    pending_approvals_count: int
    evidence_bundles_count: int
    released_bundles_count: int
    audit_chain: AuditChainVerifyOut
    dsar_metrics: DsarMetricsOut
    active_legal_holds_count: int
    retention_metrics: RetentionMetricsOut


@router.get("", response_model=OverviewSummaryOut)
async def get_overview(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> OverviewSummaryOut:
    """Aggregate posture, findings, evidence integrity, approvals, and privacy metrics."""
    posture = await get_posture_summary(db)
    findings = list((await db.execute(select(ScanFinding))).scalars().all())
    open_findings = [f for f in findings if f.status in {"fail", "warning"}]
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in open_findings:
        sev = f.severity.lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    scan_runs_count = len((await db.execute(select(ScanRun.id))).scalars().all())
    pending_approvals_count = len(
        (
            await db.execute(
                select(ApprovalRequest.id).where(ApprovalRequest.status == "pending")
            )
        )
        .scalars()
        .all()
    )
    bundles = list((await db.execute(select(EvidenceBundle))).scalars().all())
    released_bundles_count = sum(1 for b in bundles if b.status == "approved_released")
    audit_chain = await verify_audit_chain(db)

    dsars = list((await db.execute(select(DsarRequest))).scalars().all())
    today = date.today()
    dsar_open = sum(1 for d in dsars if d.status not in {"completed", "rejected"})
    dsar_overdue = sum(
        1
        for d in dsars
        if d.status not in {"completed", "rejected", "blocked_by_legal_hold"}
        and d.due_date < today
    )
    dsar_blocked = sum(1 for d in dsars if d.legal_hold_blocked)
    dsar_completed = sum(1 for d in dsars if d.status == "completed")

    active_holds_count = len(
        (await db.execute(select(LegalHold.id).where(LegalHold.status == "active")))
        .scalars()
        .all()
    )

    policies = list((await db.execute(select(RetentionPolicy))).scalars().all())
    ret_metrics = RetentionMetricsOut(
        total=len(policies),
        compliant=sum(1 for p in policies if p.status == "compliant"),
        violations=sum(1 for p in policies if p.status == "violation_over_retained"),
        suspended=sum(1 for p in policies if p.status == "legal_hold_suspended"),
        exception_granted=sum(1 for p in policies if p.status == "exception_granted"),
    )

    return OverviewSummaryOut(
        posture=posture,
        open_findings_by_severity=sev_counts,
        scan_runs_count=scan_runs_count,
        pending_approvals_count=pending_approvals_count,
        evidence_bundles_count=len(bundles),
        released_bundles_count=released_bundles_count,
        audit_chain=audit_chain,
        dsar_metrics=DsarMetricsOut(
            total=len(dsars),
            open=dsar_open,
            overdue=dsar_overdue,
            legal_hold_blocked=dsar_blocked,
            completed=dsar_completed,
        ),
        active_legal_holds_count=active_holds_count,
        retention_metrics=ret_metrics,
    )
