from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor
from app.core.config import Settings
from app.db.base import ensure_utc, utcnow
from app.db.models import ScanRun, ScheduledScan
from app.evidence.chain import record_audit_event
from app.llm.router import LLMRouter
from app.scanners.collectors import SCANNER_PRESETS
from app.scanners.engine import execute_scan
from app.scanners.repo_and_url import probe_live_url, scan_repository_files
from app.scanners.schemas import ScheduledScanCreateRequest, TargetType


async def create_scheduled_scan(
    db: AsyncSession,
    *,
    payload: ScheduledScanCreateRequest,
    actor: Actor,
) -> ScheduledScan:
    """Create a recurring compliance drift scan schedule."""
    now = utcnow()
    schedule = ScheduledScan(
        name=payload.name.strip(),
        scan_mode=payload.scan_mode,
        target_ref=payload.target_ref.strip(),
        target_type=payload.target_type,
        interval_minutes=payload.interval_minutes,
        is_active=True,
        next_run_at=now + timedelta(minutes=payload.interval_minutes),
        created_by=actor.email,
    )
    db.add(schedule)
    await db.flush()

    await record_audit_event(
        db,
        event_type="scan.schedule_created",
        actor=actor,
        entity_type="scheduled_scan",
        entity_id=schedule.id,
        action="create_schedule",
        details={
            "name": schedule.name,
            "scan_mode": schedule.scan_mode,
            "interval_minutes": schedule.interval_minutes,
        },
    )
    await db.commit()
    await db.refresh(schedule)
    return schedule


async def run_scheduled_scan(
    db: AsyncSession,
    *,
    schedule: ScheduledScan,
    settings: Settings,
    llm_router: LLMRouter,
    actor: Actor,
) -> tuple[ScheduledScan, ScanRun]:
    """Execute a scheduled scan immediately and advance its next_run_at window."""
    if schedule.scan_mode == "repo_path":
        run, _ = await scan_repository_files(
            db,
            target_name=schedule.name,
            repo_path=schedule.target_ref,
            files=[],
            auto_evaluate_controls=True,
            llm_router=llm_router,
            actor=actor,
        )
    elif schedule.scan_mode == "url_probe":
        run, _ = await probe_live_url(
            db,
            target_name=schedule.name,
            url=schedule.target_ref,
            auto_evaluate_controls=True,
            settings=settings,
            llm_router=llm_router,
            actor=actor,
        )
    else:
        preset = next(
            (p for p in SCANNER_PRESETS if p.preset_id == schedule.target_ref),
            SCANNER_PRESETS[0],
        )
        run, _ = await execute_scan(
            db,
            target_name=schedule.name,
            target_type=preset.target_type if schedule.target_type == "full_suite" else (
                schedule.target_type  # type: ignore[arg-type]
            ),
            artifact_filename=preset.artifact_filename,
            raw_bytes=preset.content.encode("utf-8"),
            content=preset.content,
            auto_evaluate_controls=True,
            llm_router=llm_router,
            actor=actor,
        )

    now = utcnow()
    schedule.last_run_at = now
    schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
    schedule.last_scan_run_id = run.id
    await db.commit()
    await db.refresh(schedule)
    return schedule, run


async def run_due_scheduled_scans(
    db: AsyncSession,
    *,
    settings: Settings,
    llm_router: LLMRouter,
    actor: Actor,
) -> list[ScanRun]:
    """Run all active scheduled scans whose next_run_at is due."""
    now = utcnow()
    schedules = list(
        (await db.execute(select(ScheduledScan).where(ScheduledScan.is_active.is_(True))))
        .scalars()
        .all()
    )
    runs: list[ScanRun] = []
    for sched in schedules:
        next_run = ensure_utc(sched.next_run_at)
        if next_run is None or next_run <= now:
            _, run = await run_scheduled_scan(
                db,
                schedule=sched,
                settings=settings,
                llm_router=llm_router,
                actor=actor,
            )
            runs.append(run)
    return runs


async def get_schedule_or_404(db: AsyncSession, schedule_id: str) -> ScheduledScan:
    sched = await db.get(ScheduledScan, schedule_id)
    if sched is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scheduled scan '{schedule_id}' not found.",
        )
    return sched


def normalize_target_type(value: str) -> TargetType:
    return value  # type: ignore[return-value]
