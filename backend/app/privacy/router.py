from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, get_current_actor, require_roles, resolve_settings
from app.db.models import DsarRequest, LegalHold, RetentionException, RetentionPolicy
from app.db.session import get_db
from app.llm.router import LLMRouter, get_llm_router
from app.privacy.schemas import (
    DsarCreateRequest,
    DsarRequestOut,
    LegalHoldCreateRequest,
    LegalHoldOut,
    LegalHoldReleaseRequest,
    RetentionExceptionCreateRequest,
    RetentionExceptionOut,
    RetentionPolicyCreateRequest,
    RetentionPolicyOut,
)
from app.privacy.service import (
    create_dsar,
    create_legal_hold,
    create_retention_policy,
    prepare_dsar_fulfillment,
    release_legal_hold,
    request_retention_exception,
    verify_retention_policies,
)

router = APIRouter(prefix="/privacy", tags=["privacy"])


@router.get("/dsars", response_model=list[DsarRequestOut])
async def list_dsars(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[DsarRequest]:
    """List tracked DSAR requests ordered newest first."""
    stmt = select(DsarRequest).order_by(DsarRequest.created_at.desc())
    return list((await db.execute(stmt)).scalars().all())


@router.post("/dsars", response_model=DsarRequestOut, status_code=status.HTTP_201_CREATED)
async def create_dsar_endpoint(
    payload: DsarCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> DsarRequest:
    """Register a new DSAR access/erasure/portability request with SLA tracking."""
    settings = resolve_settings(request)
    return await create_dsar(db, payload=payload, settings=settings, actor=actor)


@router.post("/dsars/{dsar_id}/prepare-fulfillment", response_model=DsarRequestOut)
async def prepare_dsar_fulfillment_endpoint(
    dsar_id: str,
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> DsarRequest:
    """Validate legal holds, assemble redacted export manifest, and queue HITL release."""
    return await prepare_dsar_fulfillment(
        db,
        dsar_id=dsar_id,
        llm_router=llm_router,
        actor=actor,
    )


@router.get("/legal-holds", response_model=list[LegalHoldOut])
async def list_legal_holds(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[LegalHold]:
    """List active and released legal holds."""
    stmt = select(LegalHold).order_by(LegalHold.placed_at.desc())
    return list((await db.execute(stmt)).scalars().all())


@router.post("/legal-holds", response_model=LegalHoldOut, status_code=status.HTTP_201_CREATED)
async def create_legal_hold_endpoint(
    payload: LegalHoldCreateRequest,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("compliance_officer", "admin")),
) -> LegalHold:
    """Place a new active legal hold blocking erasure DSARs and automated purges."""
    return await create_legal_hold(db, payload=payload, actor=actor)


@router.post("/legal-holds/{hold_id}/release", response_model=LegalHoldOut)
async def release_legal_hold_endpoint(
    hold_id: str,
    payload: LegalHoldReleaseRequest,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("compliance_officer", "admin")),
) -> LegalHold:
    """Release an active legal hold and re-evaluate blocked DSARs & retention schedules."""
    return await release_legal_hold(
        db,
        hold_id=hold_id,
        reason=payload.reason,
        actor=actor,
    )


@router.get("/retention-policies", response_model=list[RetentionPolicyOut])
async def list_retention_policies(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[RetentionPolicy]:
    """List registered data retention schedules and verification statuses."""
    stmt = select(RetentionPolicy).order_by(RetentionPolicy.policy_code.asc())
    return list((await db.execute(stmt)).scalars().all())


@router.post(
    "/retention-policies",
    response_model=RetentionPolicyOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_retention_policy_endpoint(
    payload: RetentionPolicyCreateRequest,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> RetentionPolicy:
    """Register a new retention policy and evaluate its compliance status."""
    return await create_retention_policy(db, payload=payload, actor=actor)


@router.post("/retention-policies/verify", response_model=list[RetentionPolicyOut])
async def verify_retention_policies_endpoint(
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> list[RetentionPolicy]:
    """Verify all retention policies against oldest record ages, holds, and exceptions."""
    return await verify_retention_policies(db, actor=actor)


@router.get("/retention-exceptions", response_model=list[RetentionExceptionOut])
async def list_retention_exceptions(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[RetentionException]:
    """List retention extension exception requests."""
    stmt = select(RetentionException).order_by(RetentionException.created_at.desc())
    return list((await db.execute(stmt)).scalars().all())


@router.post(
    "/retention-policies/{policy_id}/exceptions",
    response_model=RetentionExceptionOut,
    status_code=status.HTTP_201_CREATED,
)
async def request_retention_exception_endpoint(
    policy_id: str,
    payload: RetentionExceptionCreateRequest,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> RetentionException:
    """Request a time-bounded retention exception queued for HITL officer approval."""
    return await request_retention_exception(
        db,
        policy_id=policy_id,
        payload=payload,
        actor=actor,
    )
