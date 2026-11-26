import hashlib
import hmac
import ipaddress
import secrets
from datetime import date, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.alerts.schemas import WebhookCreateRequest
from app.core.auth import Actor
from app.db.base import ensure_utc, utcnow
from app.db.models import AlertEvent, AlertWebhook, Control, DsarRequest, RetentionException
from app.evidence.chain import canonical_json, record_audit_event


def validate_webhook_url(url: str) -> str:
    """Validate webhook URL scheme and block metadata/link-local SSRF addresses."""
    cleaned = url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Webhook target_url must use http:// or https:// with a valid hostname.",
        )
    host = parsed.hostname.lower()
    if host in {"169.254.169.254", "metadata.google.internal"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Blocked unsafe metadata webhook host '{host}'.",
        )
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Blocked link-local or multicast webhook IP '{host}'.",
            )
    except ValueError:
        pass
    return cleaned


async def create_webhook(
    db: AsyncSession,
    *,
    payload: WebhookCreateRequest,
    actor: Actor,
) -> AlertWebhook:
    """Register an HMAC-signed alert webhook subscription."""
    safe_url = validate_webhook_url(payload.target_url)
    secret = payload.secret_hmac.strip() or secrets.token_hex(24)
    hook = AlertWebhook(
        name=payload.name.strip(),
        target_url=safe_url,
        event_types_json=[e.strip() for e in payload.event_types if e.strip()],
        secret_hmac=secret,
        is_active=True,
        created_by=actor.email,
    )
    db.add(hook)
    await db.flush()

    await record_audit_event(
        db,
        event_type="alerts.webhook_created",
        actor=actor,
        entity_type="alert_webhook",
        entity_id=hook.id,
        action="create_webhook",
        details={"name": hook.name, "target_url": hook.target_url},
    )
    await db.commit()
    await db.refresh(hook)
    return hook


async def delete_webhook(db: AsyncSession, *, webhook_id: str, actor: Actor) -> None:
    """Delete an alert webhook subscription."""
    hook = await db.get(AlertWebhook, webhook_id)
    if hook is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found.",
        )
    hook_name = hook.name
    await db.delete(hook)
    await record_audit_event(
        db,
        event_type="alerts.webhook_deleted",
        actor=actor,
        entity_type="alert_webhook",
        entity_id=webhook_id,
        action="delete_webhook",
        details={"name": hook_name},
    )
    await db.commit()


async def _dispatch_webhooks(
    db: AsyncSession,
    alerts: list[AlertEvent],
    *,
    http_client: httpx.AsyncClient | None = None,
) -> None:
    if not alerts:
        return
    hooks = list(
        (await db.execute(select(AlertWebhook).where(AlertWebhook.is_active.is_(True))))
        .scalars()
        .all()
    )
    if not hooks:
        return

    async def _send_one(client: httpx.AsyncClient, hook: AlertWebhook, alert: AlertEvent) -> bool:
        body_dict: dict[str, Any] = {
            "event": "alert.opened",
            "alert_id": alert.id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "title": alert.title,
            "detail": alert.detail,
            "entity_type": alert.entity_type,
            "entity_id": alert.entity_id,
            "created_at": alert.created_at.isoformat(),
        }
        body_bytes = canonical_json(body_dict).encode("utf-8")
        sig = hmac.new(
            hook.secret_hmac.encode("utf-8"), body_bytes, hashlib.sha256
        ).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "X-Auditor-Event": "alert.opened",
            "X-Auditor-Signature": f"sha256={sig}",
        }
        try:
            resp = await client.post(hook.target_url, content=body_bytes, headers=headers)
            hook.last_delivery_status = f"{resp.status_code}"
            return 200 <= resp.status_code < 300
        except Exception as exc:
            hook.last_delivery_status = f"error: {str(exc)[:80]}"
            return False

    if http_client is not None:
        for alert in alerts:
            for hook in hooks:
                types = set(hook.event_types_json or [])
                if (not types or alert.alert_type in types) and await _send_one(
                    http_client, hook, alert
                ):
                    alert.dispatched_webhooks_count += 1
    else:
        async with httpx.AsyncClient(timeout=4.0) as client:
            for alert in alerts:
                for hook in hooks:
                    types = set(hook.event_types_json or [])
                    if (not types or alert.alert_type in types) and await _send_one(
                        client, hook, alert
                    ):
                        alert.dispatched_webhooks_count += 1


async def evaluate_drift_alerts(
    db: AsyncSession,
    *,
    actor: Actor,
    http_client: httpx.AsyncClient | None = None,
) -> list[AlertEvent]:
    """Scan posture, DSAR SLAs, waivers, and retention exceptions for open drift alerts."""
    existing_rows = (
        await db.execute(
            select(AlertEvent.alert_type, AlertEvent.entity_id).where(AlertEvent.status == "open")
        )
    ).all()
    existing_open: set[tuple[str, str]] = {(str(r[0]), str(r[1])) for r in existing_rows}

    candidates: list[AlertEvent] = []
    now = utcnow()
    today = date.today()

    def _queue(
        *,
        alert_type: str,
        severity: str,
        title: str,
        detail: str,
        entity_type: str,
        entity_id: str,
    ) -> None:
        if (alert_type, entity_id) in existing_open:
            return
        existing_open.add((alert_type, entity_id))
        candidates.append(
            AlertEvent(
                alert_type=alert_type,
                severity=severity,
                title=title,
                detail=detail,
                entity_type=entity_type,
                entity_id=entity_id,
                status="open",
            )
        )

    controls = list((await db.execute(select(Control))).scalars().all())
    for ctrl in controls:
        if ctrl.status == "failing" and ctrl.severity in {"critical", "high"}:
            _queue(
                alert_type="control_regression",
                severity=ctrl.severity,
                title=f"{ctrl.control_code} ({ctrl.framework}) failing",
                detail=ctrl.evidence_summary or ctrl.title,
                entity_type="control",
                entity_id=ctrl.id,
            )
        elif ctrl.status == "waived":
            exp = ensure_utc(ctrl.waiver_expires_at)
            if exp is not None and exp <= now + timedelta(days=7):
                _queue(
                    alert_type="waiver_expiring",
                    severity="high",
                    title=f"Waiver expiring for {ctrl.control_code}",
                    detail=f"Control waiver expires on {exp.date().isoformat()}.",
                    entity_type="control",
                    entity_id=ctrl.id,
                )

    dsars = list((await db.execute(select(DsarRequest))).scalars().all())
    for dsar in dsars:
        if dsar.status in {"completed", "rejected", "blocked_by_legal_hold"}:
            continue
        if dsar.due_date < today:
            _queue(
                alert_type="dsar_overdue",
                severity="critical",
                title=f"DSAR {dsar.reference_code} past statutory SLA",
                detail=f"{dsar.regulation} {dsar.request_type} due on {dsar.due_date.isoformat()}.",
                entity_type="dsar_request",
                entity_id=dsar.id,
            )
        elif dsar.due_date <= today + timedelta(days=7):
            _queue(
                alert_type="dsar_sla_warning",
                severity="high",
                title=f"DSAR {dsar.reference_code} due within 7 days",
                detail=f"{dsar.regulation} {dsar.request_type} due on {dsar.due_date.isoformat()}.",
                entity_type="dsar_request",
                entity_id=dsar.id,
            )

    exceptions = list(
        (
            await db.execute(
                select(RetentionException).where(RetentionException.status == "approved")
            )
        )
        .scalars()
        .all()
    )
    for exc in exceptions:
        if exc.expires_at <= today + timedelta(days=14):
            _queue(
                alert_type="retention_exception_expiring",
                severity="medium",
                title="Approved retention exception expiring soon",
                detail=(
                    f"Extension to {exc.requested_retention_days}d expires on "
                    f"{exc.expires_at.isoformat()}."
                ),
                entity_type="retention_exception",
                entity_id=exc.id,
            )

    for alert in candidates:
        db.add(alert)
    await db.flush()

    await _dispatch_webhooks(db, candidates, http_client=http_client)

    await record_audit_event(
        db,
        event_type="alerts.evaluated",
        actor=actor,
        entity_type="alert_event",
        entity_id="batch",
        action="evaluate_alerts",
        details={"new_alerts_count": len(candidates)},
    )
    await db.commit()
    for alert in candidates:
        await db.refresh(alert)
    return candidates


async def update_alert_status(
    db: AsyncSession,
    *,
    alert_id: str,
    new_status: str,
    actor: Actor,
) -> AlertEvent:
    """Acknowledge or resolve an alert event."""
    alert = await db.get(AlertEvent, alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )
    alert.status = new_status
    alert.acknowledged_by = actor.email
    alert.acknowledged_at = utcnow()

    await record_audit_event(
        db,
        event_type="alerts.updated",
        actor=actor,
        entity_type="alert_event",
        entity_id=alert.id,
        action=new_status,
        details={"alert_type": alert.alert_type, "status": new_status},
    )
    await db.commit()
    await db.refresh(alert)
    return alert
