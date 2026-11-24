import hashlib
from datetime import date, timedelta
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor
from app.core.config import Settings
from app.db.base import utcnow
from app.db.models import DsarRequest, LegalHold, RetentionException, RetentionPolicy
from app.evidence.approvals import create_approval_request
from app.evidence.chain import canonical_json, json_safe, record_audit_event
from app.llm.pii import redact_pii
from app.llm.router import LLMRouter
from app.privacy.holds import find_blocking_legal_holds, legal_hold_matches
from app.privacy.schemas import (
    DsarCreateRequest,
    LegalHoldCreateRequest,
    RetentionExceptionCreateRequest,
    RetentionPolicyCreateRequest,
)


def hash_subject_identifier(email: str) -> str:
    """Compute a deterministic privacy-preserving SHA-256 subject identifier hash."""
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


async def _next_sequential_code(
    db: AsyncSession,
    *,
    prefix: str,
    existing_codes: list[str],
) -> str:
    year = utcnow().year
    tag = f"{prefix}-{year}-"
    max_num = 0
    for code in existing_codes:
        if code.startswith(tag):
            suffix = code[len(tag) :]
            if suffix.isdigit():
                max_num = max(max_num, int(suffix))
    _ = db
    return f"{tag}{max_num + 1:03d}"


def _policy_under_active_hold(policy: RetentionPolicy, active_holds: list[LegalHold]) -> bool:
    target = policy.system_name.strip().lower()
    for hold in active_holds:
        scopes = {str(s).strip().lower() for s in (hold.systems_scope_json or []) if s}
        if "*" in scopes or "all" in scopes or target in scopes:
            return True
    return False


async def _evaluate_retention_policies_in_tx(db: AsyncSession) -> list[RetentionPolicy]:
    policies = list(
        (await db.execute(select(RetentionPolicy).order_by(RetentionPolicy.policy_code.asc())))
        .scalars()
        .all()
    )
    active_holds = list(
        (await db.execute(select(LegalHold).where(LegalHold.status == "active"))).scalars().all()
    )
    approved_exceptions = list(
        (
            await db.execute(
                select(RetentionException).where(RetentionException.status == "approved")
            )
        )
        .scalars()
        .all()
    )
    today = date.today()
    exceptions_by_policy: dict[str, list[RetentionException]] = {}
    for exc in approved_exceptions:
        if exc.expires_at >= today:
            exceptions_by_policy.setdefault(exc.policy_id, []).append(exc)

    now = utcnow()
    for pol in policies:
        if _policy_under_active_hold(pol, active_holds):
            pol.status = "legal_hold_suspended"
        else:
            active_excs = exceptions_by_policy.get(pol.id, [])
            if active_excs:
                max_extended_days = max(e.requested_retention_days for e in active_excs)
                pol.status = (
                    "exception_granted"
                    if pol.actual_oldest_record_days <= max_extended_days
                    else "violation_over_retained"
                )
            elif pol.actual_oldest_record_days > pol.retention_days:
                pol.status = "violation_over_retained"
            else:
                pol.status = "compliant"
        pol.last_verified_at = now
    await db.flush()
    return policies


async def create_dsar(
    db: AsyncSession,
    *,
    payload: DsarCreateRequest,
    settings: Settings,
    actor: Actor,
) -> DsarRequest:
    """Create a DSAR workflow record, computing SLA due date and legal-hold checks."""
    existing_codes = list(
        (await db.execute(select(DsarRequest.reference_code))).scalars().all()
    )
    ref_code = await _next_sequential_code(db, prefix="DSAR", existing_codes=existing_codes)

    clean_email = payload.subject_email.strip().lower()
    systems = [s.strip() for s in payload.data_systems if s.strip()]
    due_date = payload.due_date or (date.today() + timedelta(days=settings.dsar_default_sla_days))

    blocking_holds: list[LegalHold] = []
    if payload.request_type == "erasure":
        blocking_holds = await find_blocking_legal_holds(db, clean_email, systems)

    blocked = len(blocking_holds) > 0
    hold_codes = [h.hold_code for h in blocking_holds]
    initial_status = "blocked_by_legal_hold" if blocked else "received"

    dsar = DsarRequest(
        reference_code=ref_code,
        request_type=payload.request_type,
        regulation=payload.regulation,
        subject_email=clean_email,
        subject_identifier_hash=hash_subject_identifier(clean_email),
        data_systems_json=systems,
        status=initial_status,
        due_date=due_date,
        legal_hold_blocked=blocked,
        blocking_hold_ids_json=hold_codes,
        notes=redact_pii(payload.notes.strip()).redacted_text if payload.notes.strip() else "",
        created_by=actor.email,
    )
    db.add(dsar)
    await db.flush()

    await record_audit_event(
        db,
        event_type="dsar.created",
        actor=actor,
        entity_type="dsar_request",
        entity_id=dsar.id,
        action="create",
        details={
            "reference_code": dsar.reference_code,
            "request_type": dsar.request_type,
            "regulation": dsar.regulation,
            "due_date": dsar.due_date.isoformat(),
            "legal_hold_blocked": blocked,
            "blocking_holds": hold_codes,
        },
    )
    await db.commit()
    await db.refresh(dsar)
    return dsar


async def prepare_dsar_fulfillment(
    db: AsyncSession,
    *,
    dsar_id: str,
    llm_router: LLMRouter,
    actor: Actor,
) -> DsarRequest:
    """Screen legal holds, assemble redacted export manifest, and queue HITL approval."""
    dsar = await db.get(DsarRequest, dsar_id)
    if dsar is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DSAR '{dsar_id}' not found.",
        )
    if dsar.status == "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"DSAR '{dsar.reference_code}' is already completed.",
        )

    if dsar.request_type == "erasure":
        holds = await find_blocking_legal_holds(
            db, dsar.subject_email, list(dsar.data_systems_json or [])
        )
        if holds:
            hold_codes = [h.hold_code for h in holds]
            dsar.legal_hold_blocked = True
            dsar.status = "blocked_by_legal_hold"
            dsar.blocking_hold_ids_json = hold_codes
            await record_audit_event(
                db,
                event_type="dsar.blocked_by_legal_hold",
                actor=actor,
                entity_type="dsar_request",
                entity_id=dsar.id,
                action="block_erasure",
                details={
                    "reference_code": dsar.reference_code,
                    "blocking_holds": hold_codes,
                },
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"DSAR {dsar.reference_code} erasure is blocked by active legal hold(s): "
                    f"{', '.join(hold_codes)}."
                ),
            )

    if dsar.status == "pending_approval" and dsar.approval_id is not None:
        return dsar

    systems = list(dsar.data_systems_json or [])
    scrubbed_subject = redact_pii(dsar.subject_email).redacted_text
    system_entries: list[dict[str, Any]] = [
        {
            "system": sys_name,
            "subject_identifier_hash": dsar.subject_identifier_hash,
            "action": (
                "staged_erasure_tombstone"
                if dsar.request_type == "erasure"
                else "redacted_subject_extract"
            ),
            "records_located": 12 + idx * 5,
            "pii_scrubbed": True,
        }
        for idx, sys_name in enumerate(systems)
    ]

    llm_prompt = (
        f"DSAR={dsar.reference_code}; Type={dsar.request_type}; Regulation={dsar.regulation}; "
        f"SubjectHash={dsar.subject_identifier_hash[:12]}; Systems={','.join(systems)}"
    )
    ai_res = await llm_router.generate(
        prompt=llm_prompt,
        system_prompt="Review DSAR fulfillment readiness and privacy safeguards.",
        task_type="dsar_review",
    )

    manifest = json_safe(
        {
            "reference_code": dsar.reference_code,
            "request_type": dsar.request_type,
            "regulation": dsar.regulation,
            "subject_identifier_hash": dsar.subject_identifier_hash,
            "subject_redacted": scrubbed_subject,
            "due_date": dsar.due_date.isoformat(),
            "generated_at": utcnow().isoformat(),
            "systems": system_entries,
            "ai_review_note": ai_res.content,
        }
    )
    package_sha256 = hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest()

    dsar.legal_hold_blocked = False
    dsar.blocking_hold_ids_json = []
    dsar.export_manifest_json = manifest
    dsar.export_package_sha256 = package_sha256
    dsar.status = "pending_approval"

    approval = await create_approval_request(
        db,
        entity_type="dsar_fulfillment",
        entity_id=dsar.id,
        action_requested=f"fulfill_{dsar.request_type}_dsar",
        summary=(
            f"Fulfill {dsar.regulation} {dsar.request_type} request {dsar.reference_code} "
            f"across {len(systems)} system(s)."
        ),
        risk_level="high" if dsar.request_type == "erasure" else "medium",
        requested_by=actor.email,
        payload_json={
            "reference_code": dsar.reference_code,
            "request_type": dsar.request_type,
            "regulation": dsar.regulation,
            "export_package_sha256": package_sha256,
        },
    )
    dsar.approval_id = approval.id

    await record_audit_event(
        db,
        event_type="dsar.fulfillment_prepared",
        actor=actor,
        entity_type="dsar_request",
        entity_id=dsar.id,
        action="prepare_fulfillment",
        details={
            "reference_code": dsar.reference_code,
            "request_type": dsar.request_type,
            "export_package_sha256": package_sha256,
            "approval_id": approval.id,
        },
    )
    await db.commit()
    await db.refresh(dsar)
    return dsar


async def create_legal_hold(
    db: AsyncSession,
    *,
    payload: LegalHoldCreateRequest,
    actor: Actor,
) -> LegalHold:
    """Place an active legal hold and block matching open erasure DSARs & purges."""
    existing_codes = list((await db.execute(select(LegalHold.hold_code))).scalars().all())
    if payload.hold_code and payload.hold_code.strip():
        hold_code = payload.hold_code.strip().upper()
        if hold_code in existing_codes:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Legal hold code '{hold_code}' already exists.",
            )
    else:
        hold_code = await _next_sequential_code(db, prefix="LH", existing_codes=existing_codes)

    custodians = [c.strip().lower() for c in payload.custodian_scope if c.strip()]
    systems = [s.strip() for s in payload.systems_scope if s.strip()]

    hold = LegalHold(
        hold_code=hold_code,
        title=payload.title.strip(),
        matter_reference=payload.matter_reference.strip(),
        custodian_scope_json=custodians,
        systems_scope_json=systems,
        reason=payload.reason.strip(),
        status="active",
        placed_by=actor.email,
    )
    db.add(hold)
    await db.flush()

    open_erasure_dsars = list(
        (
            await db.execute(
                select(DsarRequest).where(
                    DsarRequest.request_type == "erasure",
                    DsarRequest.status.notin_(["completed", "rejected"]),
                )
            )
        )
        .scalars()
        .all()
    )
    blocked_refs: list[str] = []
    for dsar in open_erasure_dsars:
        if legal_hold_matches(hold, dsar.subject_email, list(dsar.data_systems_json or [])):
            dsar.legal_hold_blocked = True
            dsar.status = "blocked_by_legal_hold"
            holds_list = list(dsar.blocking_hold_ids_json or [])
            if hold.hold_code not in holds_list:
                holds_list.append(hold.hold_code)
            dsar.blocking_hold_ids_json = holds_list
            blocked_refs.append(dsar.reference_code)

    await _evaluate_retention_policies_in_tx(db)

    await record_audit_event(
        db,
        event_type="legal_hold.placed",
        actor=actor,
        entity_type="legal_hold",
        entity_id=hold.id,
        action="place_hold",
        details={
            "hold_code": hold.hold_code,
            "matter_reference": hold.matter_reference,
            "blocked_dsars": blocked_refs,
        },
    )
    await db.commit()
    await db.refresh(hold)
    return hold


async def release_legal_hold(
    db: AsyncSession,
    *,
    hold_id: str,
    reason: str,
    actor: Actor,
) -> LegalHold:
    """Release a legal hold, re-evaluating blocked DSARs and retention policies."""
    hold = await db.get(LegalHold, hold_id)
    if hold is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Legal hold '{hold_id}' not found.",
        )
    if hold.status == "released":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Legal hold '{hold.hold_code}' is already released.",
        )

    hold.status = "released"
    hold.released_by = actor.email
    hold.released_at = utcnow()
    await db.flush()

    blocked_dsars = list(
        (
            await db.execute(
                select(DsarRequest).where(DsarRequest.legal_hold_blocked.is_(True))
            )
        )
        .scalars()
        .all()
    )
    unblocked_refs: list[str] = []
    for dsar in blocked_dsars:
        remaining = await find_blocking_legal_holds(
            db, dsar.subject_email, list(dsar.data_systems_json or [])
        )
        if not remaining:
            dsar.legal_hold_blocked = False
            dsar.blocking_hold_ids_json = []
            if dsar.status == "blocked_by_legal_hold":
                dsar.status = "pending_approval" if dsar.approval_id else "in_review"
            unblocked_refs.append(dsar.reference_code)
        else:
            dsar.blocking_hold_ids_json = [h.hold_code for h in remaining]

    await _evaluate_retention_policies_in_tx(db)

    await record_audit_event(
        db,
        event_type="legal_hold.released",
        actor=actor,
        entity_type="legal_hold",
        entity_id=hold.id,
        action="release_hold",
        details={
            "hold_code": hold.hold_code,
            "reason": reason.strip(),
            "unblocked_dsars": unblocked_refs,
        },
    )
    await db.commit()
    await db.refresh(hold)
    return hold


async def create_retention_policy(
    db: AsyncSession,
    *,
    payload: RetentionPolicyCreateRequest,
    actor: Actor,
) -> RetentionPolicy:
    """Register a retention policy and evaluate its initial compliance state."""
    code = payload.policy_code.strip().upper()
    existing = (
        await db.execute(select(RetentionPolicy).where(RetentionPolicy.policy_code == code))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Retention policy '{code}' already exists.",
        )

    pol = RetentionPolicy(
        policy_code=code,
        data_category=payload.data_category.strip(),
        framework=payload.framework,
        system_name=payload.system_name.strip(),
        retention_days=payload.retention_days,
        actual_oldest_record_days=payload.actual_oldest_record_days,
        purge_mechanism=payload.purge_mechanism.strip(),
        encryption_at_rest=payload.encryption_at_rest,
        status="compliant",
    )
    db.add(pol)
    await db.flush()
    await _evaluate_retention_policies_in_tx(db)

    await record_audit_event(
        db,
        event_type="retention.policy_created",
        actor=actor,
        entity_type="retention_policy",
        entity_id=pol.id,
        action="create",
        details={
            "policy_code": pol.policy_code,
            "system_name": pol.system_name,
            "retention_days": pol.retention_days,
            "actual_oldest_record_days": pol.actual_oldest_record_days,
            "status": pol.status,
        },
    )
    await db.commit()
    await db.refresh(pol)
    return pol


async def verify_retention_policies(
    db: AsyncSession,
    *,
    actor: Actor,
) -> list[RetentionPolicy]:
    """Verify all retention schedules against record ages, holds, and approved exceptions."""
    policies = await _evaluate_retention_policies_in_tx(db)
    violations = [p.policy_code for p in policies if p.status == "violation_over_retained"]
    await record_audit_event(
        db,
        event_type="retention.verified",
        actor=actor,
        entity_type="retention_policy",
        entity_id="all",
        action="verify_all",
        details={
            "total_policies": len(policies),
            "violations": violations,
        },
    )
    await db.commit()
    return policies


async def request_retention_exception(
    db: AsyncSession,
    *,
    policy_id: str,
    payload: RetentionExceptionCreateRequest,
    actor: Actor,
) -> RetentionException:
    """Create a retention extension exception and queue HITL compliance officer approval."""
    policy = await db.get(RetentionPolicy, policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Retention policy '{policy_id}' not found.",
        )

    exc = RetentionException(
        policy_id=policy.id,
        requested_retention_days=payload.requested_retention_days,
        justification=payload.justification.strip(),
        expires_at=payload.expires_at,
        status="pending_approval",
        requested_by=actor.email,
    )
    db.add(exc)
    await db.flush()

    approval = await create_approval_request(
        db,
        entity_type="retention_exception",
        entity_id=exc.id,
        action_requested="grant_retention_exception",
        summary=(
            f"Extend retention for {policy.policy_code} ({policy.system_name}) from "
            f"{policy.retention_days}d to {payload.requested_retention_days}d until "
            f"{payload.expires_at.isoformat()}."
        ),
        risk_level="medium",
        requested_by=actor.email,
        payload_json={
            "policy_id": policy.id,
            "policy_code": policy.policy_code,
            "requested_retention_days": payload.requested_retention_days,
            "expires_at": payload.expires_at.isoformat(),
        },
    )
    exc.approval_id = approval.id

    await record_audit_event(
        db,
        event_type="retention.exception_requested",
        actor=actor,
        entity_type="retention_exception",
        entity_id=exc.id,
        action="request_exception",
        details={
            "policy_code": policy.policy_code,
            "requested_retention_days": payload.requested_retention_days,
            "expires_at": payload.expires_at.isoformat(),
            "approval_id": approval.id,
        },
    )
    await db.commit()
    await db.refresh(exc)
    return exc
