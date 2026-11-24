from datetime import timedelta
from typing import Any, Literal

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor
from app.core.config import Settings
from app.db.base import utcnow
from app.db.models import (
    ApprovalRequest,
    Control,
    ControlEvaluation,
    DsarRequest,
    EvidenceBundle,
    RetentionException,
    RetentionPolicy,
)
from app.evidence.chain import json_safe, record_audit_event
from app.privacy.holds import find_blocking_legal_holds


async def create_approval_request(
    db: AsyncSession,
    *,
    entity_type: str,
    entity_id: str,
    action_requested: str,
    summary: str,
    risk_level: str,
    requested_by: str,
    payload_json: dict[str, Any] | None = None,
) -> ApprovalRequest:
    """Create a pending human-in-the-loop compliance approval gate."""
    approval = ApprovalRequest(
        entity_type=entity_type,
        entity_id=entity_id,
        action_requested=action_requested,
        summary=summary,
        risk_level=risk_level,
        payload_json=json_safe(payload_json or {}),
        status="pending",
        requested_by=requested_by,
    )
    db.add(approval)
    await db.flush()
    return approval


async def decide_approval(
    db: AsyncSession,
    *,
    approval_id: str,
    decision: Literal["approved", "rejected"],
    notes: str,
    actor: Actor,
    settings: Settings,
) -> ApprovalRequest:
    """Approve or reject a pending HITL gate and apply domain side effects atomically."""
    approval = await db.get(ApprovalRequest, approval_id)
    if approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval request '{approval_id}' not found.",
        )
    if approval.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Approval request '{approval_id}' is already '{approval.status}'.",
        )

    if (
        settings.enforce_separation_of_duties
        and actor.email.strip().lower() == approval.requested_by.strip().lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Separation of duties violation: requester cannot decide their own approval.",
        )

    clean_notes = notes.strip() or f"{decision} by {actor.email}"

    if approval.entity_type == "dsar_fulfillment" and decision == "approved":
        dsar = await db.get(DsarRequest, approval.entity_id)
        if dsar is not None and dsar.request_type == "erasure":
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
                        f"Cannot approve erasure for {dsar.reference_code}: "
                        f"blocked by active legal hold(s) {', '.join(hold_codes)}."
                    ),
                )

    approval.status = decision
    approval.decided_by = actor.email
    approval.decision_notes = clean_notes
    approval.decided_at = utcnow()

    if approval.entity_type == "control_waiver":
        control = await db.get(Control, approval.entity_id)
        if control is not None and decision == "approved":
            waiver_days = int((approval.payload_json or {}).get("waiver_days", 30))
            expires_at = utcnow() + timedelta(days=max(1, waiver_days))
            control.status = "waived"
            control.waiver_expires_at = expires_at
            control.last_evaluated_at = utcnow()
            control.evidence_summary = (
                f"Risk waiver approved by {actor.email} until {expires_at.date().isoformat()}: "
                f"{clean_notes}"
            )
            db.add(
                ControlEvaluation(
                    control_id=control.id,
                    scan_run_id=None,
                    status="waived",
                    score=control.compliance_score,
                    passed_checks=0,
                    failed_checks=0,
                    warning_checks=0,
                    findings_snapshot_json=[
                        {
                            "type": "waiver",
                            "approval_id": approval.id,
                            "expires_at": expires_at.isoformat(),
                            "notes": clean_notes,
                        }
                    ],
                    ai_rationale=f"Control waived for {waiver_days} days: {clean_notes}",
                    llm_provider="hitl_gate",
                    evaluated_by=actor.email,
                )
            )

    elif approval.entity_type == "evidence_bundle":
        bundle = await db.get(EvidenceBundle, approval.entity_id)
        if bundle is None:
            bundle = (
                await db.execute(
                    select(EvidenceBundle).where(EvidenceBundle.approval_id == approval.id)
                )
            ).scalar_one_or_none()
        if bundle is not None:
            if decision == "approved":
                bundle.status = "approved_released"
                bundle.released_by = actor.email
                bundle.released_at = utcnow()
            else:
                bundle.status = "rejected"

    elif approval.entity_type == "dsar_fulfillment":
        dsar = await db.get(DsarRequest, approval.entity_id)
        if dsar is None:
            dsar = (
                await db.execute(select(DsarRequest).where(DsarRequest.approval_id == approval.id))
            ).scalar_one_or_none()
        if dsar is not None:
            if decision == "approved":
                dsar.status = "completed"
                dsar.completed_at = utcnow()
            else:
                dsar.status = "rejected"

    elif approval.entity_type == "retention_exception":
        exc = await db.get(RetentionException, approval.entity_id)
        if exc is None:
            exc = (
                await db.execute(
                    select(RetentionException).where(RetentionException.approval_id == approval.id)
                )
            ).scalar_one_or_none()
        if exc is not None:
            exc.status = decision
            if decision == "approved":
                exc.approved_by = actor.email
                policy = await db.get(RetentionPolicy, exc.policy_id)
                if policy is not None:
                    policy.status = "exception_granted"
                    policy.last_verified_at = utcnow()

    await record_audit_event(
        db,
        event_type="approval.decided",
        actor=actor,
        entity_type=approval.entity_type,
        entity_id=approval.entity_id,
        action=decision,
        details={
            "approval_id": approval.id,
            "decision": decision,
            "notes": clean_notes,
            "action_requested": approval.action_requested,
        },
    )
    await db.commit()
    await db.refresh(approval)
    return approval
