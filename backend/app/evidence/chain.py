import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor
from app.db.models import AuditEvent
from app.evidence.schemas import AuditChainVerifyOut, BundleVerifyOut


def canonical_json(obj: Any) -> str:
    """Serialize any JSON structure deterministically for cryptographic hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def json_safe(obj: Any) -> Any:
    """Normalize nested dicts/lists into pure JSON primitives before persistence."""
    return json.loads(canonical_json(obj))


def compute_event_hash(
    *,
    sequence_no: int,
    event_type: str,
    actor_email: str,
    actor_role: str,
    entity_type: str,
    entity_id: str,
    action: str,
    details: dict[str, Any],
    prev_hash: str,
) -> str:
    """Compute a deterministic SHA-256 hash chaining an audit event to prev_hash."""
    canonical = canonical_json(
        {
            "sequence_no": sequence_no,
            "event_type": event_type,
            "actor_email": actor_email,
            "actor_role": actor_role,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "action": action,
            "details": details,
            "prev_hash": prev_hash,
        }
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def record_audit_event(
    db: AsyncSession,
    *,
    event_type: str,
    actor: Actor,
    entity_type: str,
    entity_id: str,
    action: str,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append an immutable SHA-256 hash-chained event to the compliance audit log."""
    stmt = select(AuditEvent).order_by(AuditEvent.sequence_no.desc()).limit(1)
    latest = (await db.execute(stmt)).scalar_one_or_none()

    next_seq = (latest.sequence_no + 1) if latest is not None else 1
    prev_hash = latest.event_hash if latest is not None else "GENESIS"
    clean_details: dict[str, Any] = json_safe(details or {})

    event_hash = compute_event_hash(
        sequence_no=next_seq,
        event_type=event_type,
        actor_email=actor.email,
        actor_role=actor.role,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        details=clean_details,
        prev_hash=prev_hash,
    )
    event = AuditEvent(
        sequence_no=next_seq,
        event_type=event_type,
        actor_email=actor.email,
        actor_role=actor.role,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        details_json=clean_details,
        prev_hash=prev_hash,
        event_hash=event_hash,
    )
    db.add(event)
    await db.flush()
    return event


async def verify_audit_chain(db: AsyncSession) -> AuditChainVerifyOut:
    """Recompute every SHA-256 link in audit_events and report integrity status."""
    stmt = select(AuditEvent).order_by(AuditEvent.sequence_no.asc())
    events = list((await db.execute(stmt)).scalars().all())
    if not events:
        return AuditChainVerifyOut(
            valid=True,
            total_events=0,
            head_hash="GENESIS",
            broken_sequence_no=None,
            message="Audit trail is empty (GENESIS state verified).",
        )

    expected_prev = "GENESIS"
    expected_seq = 1
    for ev in events:
        if ev.sequence_no != expected_seq or ev.prev_hash != expected_prev:
            return AuditChainVerifyOut(
                valid=False,
                total_events=len(events),
                head_hash=events[-1].event_hash,
                broken_sequence_no=ev.sequence_no,
                message=(
                    f"Chain linkage mismatch at sequence #{ev.sequence_no}: "
                    f"expected prev_hash={expected_prev[:12]}..."
                ),
            )
        recomputed = compute_event_hash(
            sequence_no=ev.sequence_no,
            event_type=ev.event_type,
            actor_email=ev.actor_email,
            actor_role=ev.actor_role,
            entity_type=ev.entity_type,
            entity_id=ev.entity_id,
            action=ev.action,
            details=ev.details_json,
            prev_hash=ev.prev_hash,
        )
        if ev.event_hash != recomputed:
            return AuditChainVerifyOut(
                valid=False,
                total_events=len(events),
                head_hash=events[-1].event_hash,
                broken_sequence_no=ev.sequence_no,
                message=f"Hash tamper detected at sequence #{ev.sequence_no}.",
            )
        expected_prev = ev.event_hash
        expected_seq += 1

    return AuditChainVerifyOut(
        valid=True,
        total_events=len(events),
        head_hash=events[-1].event_hash,
        broken_sequence_no=None,
        message=f"All {len(events)} audit events verified intact.",
    )


def compute_bundle_item_hash(
    *,
    item_seq: int,
    item_type: str,
    item_ref: str,
    payload: dict[str, Any],
    prev_hash: str,
) -> str:
    """Compute SHA-256 digest linking an evidence bundle artifact to prev_hash."""
    canonical = canonical_json(
        {
            "item_seq": item_seq,
            "item_type": item_type,
            "item_ref": item_ref,
            "payload": payload,
            "prev_hash": prev_hash,
        }
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_manifest_sha256(manifest: dict[str, Any]) -> str:
    """Compute canonical SHA-256 digest of the complete evidence bundle manifest."""
    return hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest()


def verify_evidence_bundle_manifest(
    manifest: dict[str, Any],
    *,
    expected_manifest_sha256: str | None = None,
    expected_chain_head: str | None = None,
) -> BundleVerifyOut:
    """Independently verify every hash link and optional manifest/head digests."""
    actual_manifest_sha256 = compute_manifest_sha256(manifest)
    chain = manifest.get("evidence_chain")
    if not isinstance(chain, list):
        return BundleVerifyOut(
            valid=False,
            item_count=0,
            chain_head_hash="INVALID",
            manifest_sha256=actual_manifest_sha256,
            broken_item_seq=None,
            errors=["Manifest field 'evidence_chain' must be a list."],
            message="Bundle verification failed: missing or invalid evidence_chain.",
        )

    errors: list[str] = []
    broken_seq: int | None = None
    expected_prev = "GENESIS"
    expected_seq = 1
    last_hash = "GENESIS"

    for raw_item in chain:
        if not isinstance(raw_item, dict):
            broken_seq = broken_seq or expected_seq
            errors.append(f"Item #{expected_seq} is not an object.")
            expected_seq += 1
            continue

        item_seq = raw_item.get("item_seq")
        item_type = str(raw_item.get("item_type", ""))
        item_ref = str(raw_item.get("item_ref", ""))
        payload = raw_item.get("payload")
        prev_hash = str(raw_item.get("prev_hash", ""))
        item_hash = str(raw_item.get("item_hash", ""))

        if item_seq != expected_seq or prev_hash != expected_prev:
            broken_seq = broken_seq or expected_seq
            errors.append(
                f"Chain linkage mismatch at item #{expected_seq}: "
                f"found seq={item_seq}, prev_hash={prev_hash[:12]}."
            )

        if not isinstance(payload, dict):
            broken_seq = broken_seq or expected_seq
            errors.append(f"Item #{expected_seq} payload must be an object.")
        else:
            recomputed = compute_bundle_item_hash(
                item_seq=expected_seq,
                item_type=item_type,
                item_ref=item_ref,
                payload=payload,
                prev_hash=prev_hash,
            )
            if item_hash != recomputed:
                broken_seq = broken_seq or expected_seq
                errors.append(
                    f"Hash tamper detected at evidence item #{expected_seq} ({item_ref})."
                )

        expected_prev = item_hash
        last_hash = item_hash
        expected_seq += 1

    if expected_chain_head and last_hash != expected_chain_head:
        errors.append(
            f"Chain head mismatch: expected {expected_chain_head[:12]}..., got {last_hash[:12]}..."
        )
    if expected_manifest_sha256 and actual_manifest_sha256 != expected_manifest_sha256:
        errors.append(
            f"Manifest SHA-256 mismatch: expected {expected_manifest_sha256[:12]}..., "
            f"got {actual_manifest_sha256[:12]}..."
        )

    valid = len(errors) == 0
    if valid:
        message = f"Evidence bundle verified intact ({len(chain)} chained items)."
    else:
        message = errors[0]

    return BundleVerifyOut(
        valid=valid,
        item_count=len(chain),
        chain_head_hash=last_hash,
        manifest_sha256=actual_manifest_sha256,
        broken_item_seq=broken_seq,
        errors=errors,
        message=message,
    )
