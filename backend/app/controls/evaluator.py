from datetime import date
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.controls.catalog import BASELINE_CONTROLS
from app.controls.schemas import (
    ControlCreateRequest,
    FrameworkPostureOut,
    PostureSummaryOut,
    WaiverApprovalOut,
)
from app.core.auth import Actor
from app.db.base import ensure_utc, utcnow
from app.db.models import (
    Control,
    ControlEvaluation,
    DsarRequest,
    RetentionPolicy,
    ScanFinding,
)
from app.evidence.approvals import create_approval_request
from app.evidence.chain import json_safe, record_audit_event
from app.llm.router import LLMRouter


async def ensure_default_controls(db: AsyncSession) -> tuple[int, int]:
    """Idempotently seed baseline SOC 2, HIPAA, and GDPR controls."""
    existing_codes = set((await db.execute(select(Control.control_code))).scalars().all())
    created = 0
    for spec in BASELINE_CONTROLS:
        if spec["control_code"] in existing_codes:
            continue
        db.add(
            Control(
                control_code=spec["control_code"],
                framework=spec["framework"],
                category=spec["category"],
                title=spec["title"],
                description=spec["description"],
                severity=spec["severity"],
                scanner_domains_json=list(spec["scanner_domains"]),
                required_rules_json=list(spec["required_rules"]),
                owner_email=spec["owner_email"],
                remediation_guidance=spec["remediation_guidance"],
                status="not_evaluated",
                compliance_score=0.0,
            )
        )
        created += 1
    await db.flush()
    total = len((await db.execute(select(Control.id))).scalars().all())
    return created, total


async def create_custom_control(
    db: AsyncSession,
    *,
    payload: ControlCreateRequest,
    actor: Actor,
) -> Control:
    """Register a custom compliance control."""
    code = payload.control_code.strip().upper()
    existing = (
        await db.execute(select(Control).where(Control.control_code == code))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Control '{code}' already exists.",
        )

    control = Control(
        control_code=code,
        framework=payload.framework,
        category=payload.category.strip(),
        title=payload.title.strip(),
        description=payload.description.strip(),
        severity=payload.severity,
        scanner_domains_json=[d.strip().lower() for d in payload.scanner_domains if d.strip()],
        required_rules_json=[r.strip().upper() for r in payload.required_rules if r.strip()],
        owner_email=payload.owner_email.strip().lower(),
        remediation_guidance=payload.remediation_guidance.strip(),
        status="not_evaluated",
        compliance_score=0.0,
    )
    db.add(control)
    await db.flush()

    await record_audit_event(
        db,
        event_type="control.created",
        actor=actor,
        entity_type="control",
        entity_id=control.id,
        action="create",
        details={
            "control_code": control.control_code,
            "framework": control.framework,
            "required_rules": list(control.required_rules_json),
        },
    )
    await db.commit()
    await db.refresh(control)
    return control


async def _latest_findings_by_rule(db: AsyncSession) -> dict[str, ScanFinding]:
    stmt = select(ScanFinding).order_by(ScanFinding.created_at.desc())
    all_findings = list((await db.execute(stmt)).scalars().all())
    by_rule: dict[str, ScanFinding] = {}
    for finding in all_findings:
        rule_key = finding.rule_id.upper()
        if rule_key not in by_rule:
            by_rule[rule_key] = finding
    return by_rule


async def _evaluate_privacy_rule(db: AsyncSession, rule_id: str) -> dict[str, Any]:
    if rule_id == "PRIV-RET":
        policies = list((await db.execute(select(RetentionPolicy))).scalars().all())
        if not policies:
            return {
                "rule_id": rule_id,
                "status": "warning",
                "title": "Retention policies not yet registered",
                "detail": "No retention schedules configured to verify.",
            }
        violations = [p.policy_code for p in policies if p.status == "violation_over_retained"]
        if violations:
            return {
                "rule_id": rule_id,
                "status": "fail",
                "title": "Over-retained data detected",
                "detail": f"Retention ceiling violated on: {', '.join(sorted(violations))}.",
            }
        return {
            "rule_id": rule_id,
            "status": "pass",
            "title": "Retention schedules verified",
            "detail": (
                f"All {len(policies)} retention policies are compliant, suspended under hold, "
                "or covered by approved exceptions."
            ),
        }

    if rule_id == "PRIV-DSAR":
        dsars = list((await db.execute(select(DsarRequest))).scalars().all())
        if not dsars:
            return {
                "rule_id": rule_id,
                "status": "pass",
                "title": "No overdue DSAR requests",
                "detail": "DSAR queue is clear with zero overdue statutory deadlines.",
            }
        today = date.today()
        overdue = [
            d.reference_code
            for d in dsars
            if d.status not in {"completed", "rejected", "blocked_by_legal_hold"}
            and d.due_date < today
        ]
        if overdue:
            return {
                "rule_id": rule_id,
                "status": "fail",
                "title": "Overdue DSAR statutory SLA",
                "detail": f"Overdue DSARs past due_date: {', '.join(sorted(overdue))}.",
            }
        return {
            "rule_id": rule_id,
            "status": "pass",
            "title": "All active DSARs within SLA",
            "detail": f"Tracked {len(dsars)} DSAR record(s) with 0 overdue requests.",
        }

    return {
        "rule_id": rule_id,
        "status": "warning",
        "title": f"Unrecognized privacy rule {rule_id}",
        "detail": "No evaluation handler registered.",
    }


async def evaluate_control(
    db: AsyncSession,
    *,
    control: Control,
    llm_router: LLMRouter,
    actor: Actor,
    scan_run_id: str | None = None,
    latest_by_rule: dict[str, ScanFinding] | None = None,
) -> ControlEvaluation:
    """Evaluate a single compliance control against latest scan and privacy evidence."""
    now = utcnow()
    waiver_exp = ensure_utc(control.waiver_expires_at)
    if control.status == "waived" and waiver_exp is not None and waiver_exp > now:
        evaluation = ControlEvaluation(
            control_id=control.id,
            scan_run_id=scan_run_id,
            status="waived",
            score=control.compliance_score,
            passed_checks=0,
            failed_checks=0,
            warning_checks=0,
            findings_snapshot_json=[
                {"type": "waiver_active", "expires_at": waiver_exp.isoformat()}
            ],
            ai_rationale=(
                f"Active risk waiver preserved until {waiver_exp.date().isoformat()}."
            ),
            llm_provider="hitl_gate",
            evaluated_by=actor.email,
        )
        db.add(evaluation)
        control.last_evaluated_at = now
        await db.flush()
        return evaluation

    rule_map = latest_by_rule if latest_by_rule is not None else await _latest_findings_by_rule(db)
    rules = [str(r).strip().upper() for r in (control.required_rules_json or []) if r]

    passed = 0
    failed = 0
    warnings = 0
    snapshots: list[dict[str, Any]] = []
    evidence_points = 0

    for rule_id in rules:
        if rule_id.startswith("PRIV-"):
            priv_res = await _evaluate_privacy_rule(db, rule_id)
            snapshots.append(priv_res)
            evidence_points += 1
            if priv_res["status"] == "pass":
                passed += 1
            elif priv_res["status"] == "fail":
                failed += 1
            else:
                warnings += 1
            continue

        finding = rule_map.get(rule_id)
        if finding is None:
            snapshots.append(
                {
                    "rule_id": rule_id,
                    "status": "missing",
                    "title": "Awaiting scanner evidence",
                    "detail": f"No scan run has produced evidence for {rule_id} yet.",
                }
            )
            continue

        evidence_points += 1
        snapshots.append(
            {
                "rule_id": rule_id,
                "finding_id": finding.id,
                "scan_run_id": finding.scan_run_id,
                "status": finding.status,
                "severity": finding.severity,
                "title": finding.title,
                "detail": finding.detail,
            }
        )
        if finding.status == "pass":
            passed += 1
        elif finding.status == "fail":
            failed += 1
        else:
            warnings += 1

    if evidence_points == 0:
        new_status = "not_evaluated"
        score = 0.0
        summary = "No scanner or privacy evidence recorded for required rules yet."
    else:
        total_rules = max(len(rules), evidence_points)
        missing_count = max(0, len(rules) - evidence_points)
        earned = passed * 1.0 + warnings * 0.5
        score = round((earned / total_rules) * 100.0, 1)
        if failed > 0:
            new_status = "failing"
        elif warnings > 0 or missing_count > 0:
            new_status = "warning"
        else:
            new_status = "passing"
        summary = (
            f"{passed} passed, {failed} failed, {warnings} warning(s)"
            + (f", {missing_count} awaiting scan" if missing_count else "")
            + f" across {total_rules} required rule(s)."
        )

    llm_prompt = (
        f"Control={control.control_code} ({control.framework}); Status={new_status}; "
        f"Score={score}%; Checks={summary}"
    )
    ai_res = await llm_router.generate(
        prompt=llm_prompt,
        system_prompt="Provide concise audit evaluation rationale for this compliance control.",
        task_type="control_evaluation",
    )

    control.status = new_status
    control.compliance_score = score
    control.evidence_summary = summary
    control.last_evaluated_at = now

    evaluation = ControlEvaluation(
        control_id=control.id,
        scan_run_id=scan_run_id,
        status=new_status,
        score=score,
        passed_checks=passed,
        failed_checks=failed,
        warning_checks=warnings,
        findings_snapshot_json=json_safe(snapshots),
        ai_rationale=ai_res.content,
        llm_provider=ai_res.provider,
        evaluated_by=actor.email,
    )
    db.add(evaluation)
    await db.flush()

    await record_audit_event(
        db,
        event_type="control.evaluated",
        actor=actor,
        entity_type="control",
        entity_id=control.id,
        action="evaluate",
        details={
            "control_code": control.control_code,
            "framework": control.framework,
            "status": new_status,
            "score": score,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
        },
    )
    return evaluation


async def evaluate_all_controls(
    db: AsyncSession,
    *,
    framework: str | None,
    llm_router: LLMRouter,
    actor: Actor,
    scan_run_id: str | None = None,
    rule_filter: set[str] | None = None,
) -> list[Control]:
    """Evaluate all controls (optionally filtered by framework or affected rule IDs)."""
    stmt = select(Control).order_by(Control.control_code.asc())
    if framework:
        stmt = stmt.where(Control.framework == framework.strip().upper())
    controls = list((await db.execute(stmt)).scalars().all())
    if not controls:
        await ensure_default_controls(db)
        controls = list((await db.execute(stmt)).scalars().all())

    latest_by_rule = await _latest_findings_by_rule(db)
    for control in controls:
        if rule_filter is not None:
            ctrl_rules = {str(r).strip().upper() for r in (control.required_rules_json or [])}
            if not (ctrl_rules & rule_filter):
                continue
        await evaluate_control(
            db,
            control=control,
            llm_router=llm_router,
            actor=actor,
            scan_run_id=scan_run_id,
            latest_by_rule=latest_by_rule,
        )

    await db.commit()
    for control in controls:
        await db.refresh(control)
    return controls


async def request_control_waiver(
    db: AsyncSession,
    *,
    control_id: str,
    justification: str,
    waiver_days: int,
    actor: Actor,
) -> WaiverApprovalOut:
    """Create a pending HITL approval gate for waiving a control risk."""
    control = await db.get(Control, control_id)
    if control is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Control '{control_id}' not found.",
        )

    approval = await create_approval_request(
        db,
        entity_type="control_waiver",
        entity_id=control.id,
        action_requested="approve_control_waiver",
        summary=(
            f"Grant {waiver_days}-day risk waiver for {control.control_code} "
            f"({control.framework}): {justification.strip()}"
        ),
        risk_level=control.severity,
        requested_by=actor.email,
        payload_json={
            "control_code": control.control_code,
            "framework": control.framework,
            "waiver_days": waiver_days,
            "justification": justification.strip(),
        },
    )
    await record_audit_event(
        db,
        event_type="control.waiver_requested",
        actor=actor,
        entity_type="control",
        entity_id=control.id,
        action="request_waiver",
        details={
            "control_code": control.control_code,
            "waiver_days": waiver_days,
            "approval_id": approval.id,
        },
    )
    await db.commit()
    return WaiverApprovalOut(
        control_id=control.id,
        control_code=control.control_code,
        approval_id=approval.id,
        status=approval.status,
        message=f"Waiver request queued for compliance officer approval ({approval.id}).",
    )


async def get_posture_summary(db: AsyncSession) -> PostureSummaryOut:
    """Compute framework-by-framework and overall compliance posture scores."""
    controls = list(
        (await db.execute(select(Control).order_by(Control.control_code.asc()))).scalars().all()
    )
    framework_order = ["SOC2", "HIPAA", "GDPR"]
    extra_frameworks = sorted({c.framework for c in controls if c.framework not in framework_order})
    all_frameworks = framework_order + extra_frameworks

    framework_summaries: list[FrameworkPostureOut] = []
    for fw in all_frameworks:
        items = [c for c in controls if c.framework == fw]
        passing = sum(1 for c in items if c.status == "passing")
        failing = sum(1 for c in items if c.status == "failing")
        warning = sum(1 for c in items if c.status == "warning")
        waived = sum(1 for c in items if c.status == "waived")
        not_eval = sum(1 for c in items if c.status == "not_evaluated")
        if items:
            # Waived controls contribute full 100 or their score? Wait: let's average
            # compliance_score for evaluated/waived controls (waived gets max(score, 80) or
            # actual compliance_score). Better: sum effective score where waived=100.0 if score==0
            effective_scores = [
                100.0 if c.status == "waived" and c.compliance_score == 0.0 else c.compliance_score
                for c in items
            ]
            score_pct = round(sum(effective_scores) / len(items), 1)
        else:
            score_pct = 0.0
        framework_summaries.append(
            FrameworkPostureOut(
                framework=fw,
                total_controls=len(items),
                passing=passing,
                failing=failing,
                warning=warning,
                waived=waived,
                not_evaluated=not_eval,
                score_pct=score_pct,
            )
        )

    if controls:
        overall = round(
            sum(
                100.0 if c.status == "waived" and c.compliance_score == 0.0 else c.compliance_score
                for c in controls
            )
            / len(controls),
            1,
        )
    else:
        overall = 0.0

    return PostureSummaryOut(
        overall_score_pct=overall,
        total_controls=len(controls),
        frameworks=framework_summaries,
    )
