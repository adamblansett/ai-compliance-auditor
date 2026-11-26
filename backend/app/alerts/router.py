from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.alerts.schemas import AlertEventOut, AlertWebhookOut, WebhookCreateRequest
from app.alerts.service import (
    create_webhook,
    delete_webhook,
    evaluate_drift_alerts,
    update_alert_status,
)
from app.core.auth import Actor, get_current_actor, require_roles
from app.db.models import AlertEvent, AlertWebhook
from app.db.session import get_db

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertEventOut])
async def list_alerts(
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[AlertEvent]:
    """List continuous compliance drift alerts newest first."""
    stmt = select(AlertEvent).order_by(AlertEvent.created_at.desc())
    if status_filter:
        stmt = stmt.where(AlertEvent.status == status_filter.strip().lower())
    if severity:
        stmt = stmt.where(AlertEvent.severity == severity.strip().lower())
    return list((await db.execute(stmt)).scalars().all())


@router.post("/evaluate", response_model=list[AlertEventOut])
async def evaluate_alerts_endpoint(
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> list[AlertEvent]:
    """Evaluate failing controls, SLA deadlines, and expiring waivers for new drift alerts."""
    return await evaluate_drift_alerts(db, actor=actor)


@router.post("/{alert_id}/acknowledge", response_model=AlertEventOut)
async def acknowledge_alert_endpoint(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> AlertEvent:
    """Acknowledge an open compliance drift alert."""
    return await update_alert_status(db, alert_id=alert_id, new_status="acknowledged", actor=actor)


@router.post("/{alert_id}/resolve", response_model=AlertEventOut)
async def resolve_alert_endpoint(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("compliance_officer", "admin")),
) -> AlertEvent:
    """Mark a compliance drift alert as resolved."""
    return await update_alert_status(db, alert_id=alert_id, new_status="resolved", actor=actor)


@router.get("/webhooks", response_model=list[AlertWebhookOut])
async def list_webhooks(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[AlertWebhook]:
    """List registered alert webhook endpoints."""
    stmt = select(AlertWebhook).order_by(AlertWebhook.created_at.desc())
    return list((await db.execute(stmt)).scalars().all())


@router.post("/webhooks", response_model=AlertWebhookOut, status_code=status.HTTP_201_CREATED)
async def create_webhook_endpoint(
    payload: WebhookCreateRequest,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("compliance_officer", "admin")),
) -> AlertWebhook:
    """Register an HMAC-signed webhook endpoint for drift alert notifications."""
    return await create_webhook(db, payload=payload, actor=actor)


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook_endpoint(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("compliance_officer", "admin")),
) -> None:
    """Remove an alert webhook subscription."""
    await delete_webhook(db, webhook_id=webhook_id, actor=actor)
