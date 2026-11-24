from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.controls.evaluator import (
    create_custom_control,
    ensure_default_controls,
    evaluate_all_controls,
    get_posture_summary,
    request_control_waiver,
)
from app.controls.schemas import (
    ControlCreateRequest,
    ControlEvaluationOut,
    ControlOut,
    PostureSummaryOut,
    WaiverApprovalOut,
    WaiverCreateRequest,
)
from app.core.auth import Actor, get_current_actor, require_roles
from app.db.models import Control, ControlEvaluation
from app.db.session import get_db
from app.evidence.chain import record_audit_event
from app.llm.router import LLMRouter, get_llm_router

router = APIRouter(prefix="/controls", tags=["controls"])


@router.get("", response_model=list[ControlOut])
async def list_controls(
    framework: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[Control]:
    """List SOC 2, HIPAA, and GDPR controls with optional framework and status filters."""
    stmt = select(Control).order_by(Control.framework.asc(), Control.control_code.asc())
    if framework:
        stmt = stmt.where(Control.framework == framework.strip().upper())
    if status_filter:
        stmt = stmt.where(Control.status == status_filter.strip().lower())
    return list((await db.execute(stmt)).scalars().all())


@router.post("", response_model=ControlOut, status_code=status.HTTP_201_CREATED)
async def create_control_endpoint(
    payload: ControlCreateRequest,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> Control:
    """Register a custom compliance control."""
    return await create_custom_control(db, payload=payload, actor=actor)


@router.post("/seed-catalog")
async def seed_catalog_endpoint(
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> dict[str, int | str]:
    """Idempotently populate the 18 baseline SOC 2, HIPAA, and GDPR controls."""
    created, total = await ensure_default_controls(db)
    await record_audit_event(
        db,
        event_type="controls.catalog_seeded",
        actor=actor,
        entity_type="control",
        entity_id="catalog",
        action="seed_catalog",
        details={"created": created, "total": total},
    )
    await db.commit()
    return {
        "created": created,
        "total": total,
        "message": f"Baseline catalog synced ({created} created, {total} total controls).",
    }


@router.post("/evaluate", response_model=list[ControlOut])
async def evaluate_controls_endpoint(
    framework: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> list[Control]:
    """Evaluate controls (all or by framework) against latest scan and privacy evidence."""
    return await evaluate_all_controls(
        db,
        framework=framework,
        llm_router=llm_router,
        actor=actor,
    )


@router.get("/posture", response_model=PostureSummaryOut)
async def get_posture_endpoint(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> PostureSummaryOut:
    """Return compliance posture scores across SOC 2, HIPAA, and GDPR."""
    return await get_posture_summary(db)


@router.get("/{control_id}/evaluations", response_model=list[ControlEvaluationOut])
async def list_control_evaluations(
    control_id: str,
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[ControlEvaluation]:
    """Return historical evaluations for a single control."""
    stmt = (
        select(ControlEvaluation)
        .where(ControlEvaluation.control_id == control_id)
        .order_by(ControlEvaluation.evaluated_at.desc())
    )
    return list((await db.execute(stmt)).scalars().all())


@router.post("/{control_id}/waiver", response_model=WaiverApprovalOut)
async def request_waiver_endpoint(
    control_id: str,
    payload: WaiverCreateRequest,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> WaiverApprovalOut:
    """Request a time-bounded control risk waiver queued for HITL approval."""
    return await request_control_waiver(
        db,
        control_id=control_id,
        justification=payload.justification,
        waiver_days=payload.waiver_days,
        actor=actor,
    )
