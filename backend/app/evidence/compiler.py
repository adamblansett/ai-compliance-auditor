from datetime import date, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor
from app.db.base import ensure_utc, utcnow
from app.db.models import (
    AuditEvent,
    Control,
    ControlEvaluation,
    DsarRequest,
    EvidenceBundle,
    LegalHold,
    RetentionPolicy,
    ScanFinding,
    ScanRun,
)
from app.evidence.approvals import create_approval_request
from app.evidence.chain import (
    compute_bundle_item_hash,
    compute_manifest_sha256,
    json_safe,
    record_audit_event,
)
from app.llm.router import LLMRouter


async def compile_evidence_bundle(
    db: AsyncSession,
    *,
    bundle_name: str,
    frameworks: list[str],
    period_start: date | None,
    period_end: date | None,
    llm_router: LLMRouter,
    actor: Actor,
) -> EvidenceBundle:
    """Compile a SHA-256 hash-chained evidence package and queue it for HITL release."""
    resolved_end = period_end or date.today()
    resolved_start = period_start or (resolved_end - timedelta(days=90))
    if resolved_start > resolved_end:
        resolved_start, resolved_end = resolved_end, resolved_start

    norm_frameworks = sorted({f.strip().upper() for f in (frameworks or ["SOC2", "HIPAA", "GDPR"])})

    controls = list(
        (
            await db.execute(
                select(Control)
                .where(Control.framework.in_(norm_frameworks))
                .order_by(Control.control_code.asc())
            )
        )
        .scalars()
        .all()
    )
    control_ids = [c.id for c in controls]

    evaluations: list[ControlEvaluation] = []
    if control_ids:
        evaluations = list(
            (
                await db.execute(
                    select(ControlEvaluation)
                    .where(ControlEvaluation.control_id.in_(control_ids))
                    .order_by(ControlEvaluation.evaluated_at.desc())
                    .limit(50)
                )
            )
            .scalars()
            .all()
        )

    all_scans = list(
        (await db.execute(select(ScanRun).order_by(ScanRun.created_at.asc()))).scalars().all()
    )
    scans = [
        s
        for s in all_scans
        if (utc_dt := ensure_utc(s.created_at)) is not None
        and resolved_start <= utc_dt.date() <= resolved_end
    ]
    if not scans and all_scans:
        scans = all_scans[-10:]

    scan_ids = [s.id for s in scans]
    findings: list[ScanFinding] = []
    if scan_ids:
        findings = list(
            (
                await db.execute(
                    select(ScanFinding)
                    .where(ScanFinding.scan_run_id.in_(scan_ids))
                    .order_by(ScanFinding.created_at.asc(), ScanFinding.rule_id.asc())
                )
            )
            .scalars()
            .all()
        )

    dsars = list(
        (await db.execute(select(DsarRequest).order_by(DsarRequest.reference_code.asc())))
        .scalars()
        .all()
    )
    holds = list(
        (await db.execute(select(LegalHold).order_by(LegalHold.hold_code.asc()))).scalars().all()
    )
    policies = list(
        (await db.execute(select(RetentionPolicy).order_by(RetentionPolicy.policy_code.asc())))
        .scalars()
        .all()
    )
    latest_audit = (
        await db.execute(select(AuditEvent).order_by(AuditEvent.sequence_no.desc()).limit(1))
    ).scalar_one_or_none()
    audit_head_hash = latest_audit.event_hash if latest_audit is not None else "GENESIS"

    raw_items: list[tuple[str, str, dict[str, Any]]] = []
    for ctrl in controls:
        raw_items.append(
            (
                "control",
                ctrl.control_code,
                {
                    "framework": ctrl.framework,
                    "title": ctrl.title,
                    "severity": ctrl.severity,
                    "status": ctrl.status,
                    "compliance_score": ctrl.compliance_score,
                    "required_rules": list(ctrl.required_rules_json or []),
                    "last_evaluated_at": (
                        ctrl.last_evaluated_at.isoformat() if ctrl.last_evaluated_at else None
                    ),
                },
            )
        )

    for ev in evaluations:
        raw_items.append(
            (
                "control_evaluation",
                ev.id,
                {
                    "control_id": ev.control_id,
                    "status": ev.status,
                    "score": ev.score,
                    "passed_checks": ev.passed_checks,
                    "failed_checks": ev.failed_checks,
                    "warning_checks": ev.warning_checks,
                    "evaluated_at": ev.evaluated_at.isoformat(),
                },
            )
        )

    for run in scans:
        raw_items.append(
            (
                "scan_run",
                run.id,
                {
                    "target_name": run.target_name,
                    "target_type": run.target_type,
                    "artifact_filename": run.artifact_filename,
                    "artifact_sha256": run.artifact_sha256,
                    "status": run.status,
                    "risk_score": run.risk_score,
                    "created_at": run.created_at.isoformat(),
                },
            )
        )

    for f in findings:
        raw_items.append(
            (
                "scan_finding",
                f"{f.rule_id}:{f.id[:8]}",
                {
                    "scan_run_id": f.scan_run_id,
                    "rule_id": f.rule_id,
                    "domain": f.domain,
                    "severity": f.severity,
                    "status": f.status,
                    "title": f.title,
                    "evidence_hash": f.evidence_hash,
                    "mapped_controls": list(f.mapped_controls_json or []),
                },
            )
        )

    for dsar in dsars:
        raw_items.append(
            (
                "dsar_request",
                dsar.reference_code,
                {
                    "request_type": dsar.request_type,
                    "regulation": dsar.regulation,
                    "subject_identifier_hash": dsar.subject_identifier_hash,
                    "status": dsar.status,
                    "due_date": dsar.due_date.isoformat(),
                    "legal_hold_blocked": dsar.legal_hold_blocked,
                    "export_package_sha256": dsar.export_package_sha256,
                },
            )
        )

    for hold in holds:
        raw_items.append(
            (
                "legal_hold",
                hold.hold_code,
                {
                    "title": hold.title,
                    "matter_reference": hold.matter_reference,
                    "status": hold.status,
                    "systems_scope": list(hold.systems_scope_json or []),
                },
            )
        )

    for pol in policies:
        raw_items.append(
            (
                "retention_policy",
                pol.policy_code,
                {
                    "framework": pol.framework,
                    "system_name": pol.system_name,
                    "retention_days": pol.retention_days,
                    "actual_oldest_record_days": pol.actual_oldest_record_days,
                    "status": pol.status,
                },
            )
        )

    evidence_chain: list[dict[str, Any]] = []
    prev_hash = "GENESIS"
    for seq, (item_type, item_ref, payload) in enumerate(raw_items, start=1):
        clean_payload = json_safe(payload)
        item_hash = compute_bundle_item_hash(
            item_seq=seq,
            item_type=item_type,
            item_ref=item_ref,
            payload=clean_payload,
            prev_hash=prev_hash,
        )
        evidence_chain.append(
            {
                "item_seq": seq,
                "item_type": item_type,
                "item_ref": item_ref,
                "payload": clean_payload,
                "prev_hash": prev_hash,
                "item_hash": item_hash,
            }
        )
        prev_hash = item_hash

    chain_head_hash = prev_hash
    compiled_at = utcnow().isoformat()
    manifest: dict[str, Any] = json_safe(
        {
            "bundle_name": bundle_name.strip(),
            "frameworks": norm_frameworks,
            "period_start": resolved_start.isoformat(),
            "period_end": resolved_end.isoformat(),
            "compiled_at": compiled_at,
            "compiled_by": actor.email,
            "audit_trail_head_hash": audit_head_hash,
            "summary": {
                "controls_count": len(controls),
                "passing_controls": sum(1 for c in controls if c.status == "passing"),
                "failing_controls": sum(1 for c in controls if c.status == "failing"),
                "scan_runs_count": len(scans),
                "findings_count": len(findings),
                "dsar_count": len(dsars),
                "active_legal_holds": sum(1 for h in holds if h.status == "active"),
                "retention_policies_count": len(policies),
            },
            "evidence_chain": evidence_chain,
        }
    )
    manifest_sha256 = compute_manifest_sha256(manifest)

    llm_prompt = (
        f"Bundle={bundle_name}; Frameworks={','.join(norm_frameworks)}; "
        f"Period={resolved_start.isoformat()}..{resolved_end.isoformat()}; "
        f"Items={len(evidence_chain)}; Passing={manifest['summary']['passing_controls']}/"
        f"{len(controls)}; HeadHash={chain_head_hash[:16]}"
    )
    ai_res = await llm_router.generate(
        prompt=llm_prompt,
        system_prompt="Summarize compliance evidence readiness for external audit sign-off.",
        task_type="evidence_attestation",
    )

    bundle = EvidenceBundle(
        bundle_name=bundle_name.strip(),
        frameworks_json=norm_frameworks,
        period_start=resolved_start,
        period_end=resolved_end,
        status="pending_approval",
        item_count=len(evidence_chain),
        chain_head_hash=chain_head_hash,
        manifest_sha256=manifest_sha256,
        manifest_json=manifest,
        ai_attestation_summary=ai_res.content,
        compiled_by=actor.email,
    )
    db.add(bundle)
    await db.flush()

    approval = await create_approval_request(
        db,
        entity_type="evidence_bundle",
        entity_id=bundle.id,
        action_requested="release_audit_bundle",
        summary=(
            f"Release audit bundle '{bundle.bundle_name}' ({', '.join(norm_frameworks)}, "
            f"{len(evidence_chain)} chained items) to external auditors."
        ),
        risk_level="high",
        requested_by=actor.email,
        payload_json={
            "bundle_name": bundle.bundle_name,
            "frameworks": norm_frameworks,
            "item_count": len(evidence_chain),
            "chain_head_hash": chain_head_hash,
            "manifest_sha256": manifest_sha256,
        },
    )
    bundle.approval_id = approval.id

    await record_audit_event(
        db,
        event_type="bundle.compiled",
        actor=actor,
        entity_type="evidence_bundle",
        entity_id=bundle.id,
        action="compile",
        details={
            "bundle_name": bundle.bundle_name,
            "frameworks": norm_frameworks,
            "item_count": len(evidence_chain),
            "chain_head_hash": chain_head_hash,
            "manifest_sha256": manifest_sha256,
        },
    )
    await db.commit()
    await db.refresh(bundle)
    return bundle
