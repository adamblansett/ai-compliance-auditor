import hashlib

from sqlalchemy.ext.asyncio import AsyncSession

from app.controls.evaluator import evaluate_all_controls
from app.core.auth import Actor
from app.db.models import ScanFinding, ScanRun
from app.evidence.chain import canonical_json, record_audit_event
from app.llm.pii import redact_pii
from app.llm.router import LLMRouter
from app.scanners.collectors import run_collectors
from app.scanners.schemas import TargetType

_SEVERITY_WEIGHTS = {
    "critical": 25.0,
    "high": 15.0,
    "medium": 8.0,
    "low": 3.0,
}


async def execute_scan(
    db: AsyncSession,
    *,
    target_name: str,
    target_type: TargetType,
    artifact_filename: str,
    raw_bytes: bytes,
    content: str,
    auto_evaluate_controls: bool,
    llm_router: LLMRouter,
    actor: Actor,
) -> tuple[ScanRun, list[ScanFinding]]:
    """Run deterministic collectors, persist scrubbed findings, and update controls."""
    artifact_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    scrubbed_preview = redact_pii(content[:600]).redacted_text

    collected = run_collectors(target_type, content)
    total_checks = len(collected)
    passed_checks = sum(1 for c in collected if c.status == "pass")
    failed_checks = sum(1 for c in collected if c.status == "fail")
    warning_checks = sum(1 for c in collected if c.status == "warning")

    if failed_checks > 0:
        run_status = "failed"
    elif warning_checks > 0:
        run_status = "warnings"
    else:
        run_status = "passed"

    penalty = 0.0
    for c in collected:
        if c.status == "fail":
            penalty += _SEVERITY_WEIGHTS.get(c.severity, 10.0)
        elif c.status == "warning":
            penalty += _SEVERITY_WEIGHTS.get(c.severity, 10.0) * 0.35
    risk_score = round(min(100.0, penalty), 1)

    llm_prompt = (
        f"Target={target_name} ({target_type}); Status={run_status}; RiskScore={risk_score}; "
        f"Checks={passed_checks} pass / {failed_checks} fail / {warning_checks} warn"
    )
    ai_res = await llm_router.generate(
        prompt=llm_prompt,
        system_prompt="Summarize compliance scan risk posture and remediation priority.",
        task_type="policy_scan",
    )

    run = ScanRun(
        target_name=target_name.strip(),
        target_type=target_type,
        artifact_filename=artifact_filename.strip() or "artifact.txt",
        artifact_sha256=artifact_sha256,
        artifact_preview=scrubbed_preview,
        status=run_status,
        total_checks=total_checks,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        warning_checks=warning_checks,
        risk_score=risk_score,
        ai_summary=ai_res.content,
        llm_provider=ai_res.provider,
        triggered_by=actor.email,
    )
    db.add(run)
    await db.flush()

    findings: list[ScanFinding] = []
    affected_rules: set[str] = set()
    for check in collected:
        clean_snippet = redact_pii(check.evidence_snippet).redacted_text
        evidence_hash = hashlib.sha256(
            canonical_json(
                {
                    "scan_run_id": run.id,
                    "rule_id": check.rule_id,
                    "status": check.status,
                    "evidence_snippet": clean_snippet,
                    "artifact_sha256": artifact_sha256,
                }
            ).encode("utf-8")
        ).hexdigest()
        finding = ScanFinding(
            scan_run_id=run.id,
            rule_id=check.rule_id,
            domain=check.domain,
            severity=check.severity,
            status=check.status,
            title=check.title,
            detail=check.detail,
            remediation=check.remediation,
            mapped_controls_json=list(check.mapped_controls),
            evidence_snippet=clean_snippet,
            evidence_hash=evidence_hash,
        )
        db.add(finding)
        findings.append(finding)
        affected_rules.add(check.rule_id.upper())

    await db.flush()

    await record_audit_event(
        db,
        event_type="scan.completed",
        actor=actor,
        entity_type="scan_run",
        entity_id=run.id,
        action="scan",
        details={
            "target_name": run.target_name,
            "target_type": run.target_type,
            "artifact_sha256": run.artifact_sha256,
            "status": run.status,
            "risk_score": run.risk_score,
            "failed_checks": run.failed_checks,
        },
    )

    if auto_evaluate_controls:
        await evaluate_all_controls(
            db,
            framework=None,
            llm_router=llm_router,
            actor=actor,
            scan_run_id=run.id,
            rule_filter=affected_rules,
        )
    else:
        await db.commit()

    await db.refresh(run)
    for f in findings:
        await db.refresh(f)
    return run, findings
