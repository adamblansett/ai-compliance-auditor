from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, get_current_actor, require_roles, resolve_settings
from app.db.models import ScanFinding, ScanRun, ScheduledScan
from app.db.session import get_db
from app.llm.router import LLMRouter, get_llm_router
from app.scanners.collectors import SCANNER_PRESETS
from app.scanners.engine import execute_scan
from app.scanners.repo_and_url import probe_live_url, scan_repository_files
from app.scanners.scheduler import (
    create_scheduled_scan,
    get_schedule_or_404,
    run_due_scheduled_scans,
    run_scheduled_scan,
)
from app.scanners.schemas import (
    RepoScanRequest,
    ScanFindingOut,
    ScannerPresetOut,
    ScanRequest,
    ScanRunDetailOut,
    ScanRunOut,
    ScheduledScanCreateRequest,
    ScheduledScanOut,
    TargetType,
    UrlProbeRequest,
)

router = APIRouter(prefix="/scanners", tags=["scanners"])

_MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MiB


@router.get("/presets", response_model=list[ScannerPresetOut])
async def list_scanner_presets(
    _: Actor = Depends(get_current_actor),
) -> list[ScannerPresetOut]:
    """Return built-in compliance scan artifact presets for interactive testing."""
    return list(SCANNER_PRESETS)


@router.get("/runs", response_model=list[ScanRunOut])
async def list_scan_runs(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[ScanRun]:
    """List executed scanner runs newest first."""
    stmt = select(ScanRun).order_by(ScanRun.created_at.desc())
    return list((await db.execute(stmt)).scalars().all())


@router.get("/runs/{run_id}", response_model=ScanRunDetailOut)
async def get_scan_run_detail(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> ScanRunDetailOut:
    """Return a scan run and all associated findings."""
    run = await db.get(ScanRun, run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan run '{run_id}' not found.",
        )
    findings = list(
        (
            await db.execute(
                select(ScanFinding)
                .where(ScanFinding.scan_run_id == run.id)
                .order_by(ScanFinding.rule_id.asc())
            )
        )
        .scalars()
        .all()
    )
    base = ScanRunOut.model_validate(run)
    return ScanRunDetailOut(
        **base.model_dump(),
        findings=[ScanFindingOut.model_validate(f) for f in findings],
    )


@router.get("/findings", response_model=list[ScanFindingOut])
async def list_scan_findings(
    domain: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[ScanFinding]:
    """List scanner findings with optional domain, status, and severity filters."""
    stmt = select(ScanFinding).order_by(ScanFinding.created_at.desc(), ScanFinding.rule_id.asc())
    if domain:
        stmt = stmt.where(ScanFinding.domain == domain.strip().lower())
    if status_filter:
        stmt = stmt.where(ScanFinding.status == status_filter.strip().lower())
    if severity:
        stmt = stmt.where(ScanFinding.severity == severity.strip().lower())
    return list((await db.execute(stmt)).scalars().all())


@router.post("/scan", response_model=ScanRunDetailOut, status_code=status.HTTP_201_CREATED)
async def run_inline_scan(
    payload: ScanRequest,
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> ScanRunDetailOut:
    """Scan inline configuration, log, RBAC policy, or SOP text."""
    raw_bytes = payload.content.encode("utf-8")
    run, findings = await execute_scan(
        db,
        target_name=payload.target_name,
        target_type=payload.target_type,
        artifact_filename=payload.artifact_filename,
        raw_bytes=raw_bytes,
        content=payload.content,
        auto_evaluate_controls=payload.auto_evaluate_controls,
        llm_router=llm_router,
        actor=actor,
    )
    base = ScanRunOut.model_validate(run)
    return ScanRunDetailOut(
        **base.model_dump(),
        findings=[ScanFindingOut.model_validate(f) for f in findings],
    )


@router.post("/upload", response_model=ScanRunDetailOut, status_code=status.HTTP_201_CREATED)
async def upload_and_scan_file(
    file: UploadFile = File(...),
    target_name: str = Form(default=""),
    target_type: TargetType = Form(default="full_suite"),
    auto_evaluate_controls: bool = Form(default=True),
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> ScanRunDetailOut:
    """Upload a configuration, IAM policy, log, or SOP artifact (<= 2 MiB) for scanning."""
    raw_bytes = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(raw_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Uploaded artifact exceeds 2 MiB limit.",
        )
    if not raw_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    text_content = raw_bytes.decode("utf-8", errors="replace")
    filename = file.filename or "uploaded-artifact.txt"
    resolved_target = target_name.strip() or filename

    run, findings = await execute_scan(
        db,
        target_name=resolved_target,
        target_type=target_type,
        artifact_filename=filename,
        raw_bytes=raw_bytes,
        content=text_content,
        auto_evaluate_controls=auto_evaluate_controls,
        llm_router=llm_router,
        actor=actor,
    )
    base = ScanRunOut.model_validate(run)
    return ScanRunDetailOut(
        **base.model_dump(),
        findings=[ScanFindingOut.model_validate(f) for f in findings],
    )


@router.post("/scan-repo", response_model=ScanRunDetailOut, status_code=status.HTTP_201_CREATED)
async def scan_repo_endpoint(
    payload: RepoScanRequest,
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> ScanRunDetailOut:
    """Scan a multi-file repository directory or inline file bundle across all domains."""
    run, findings = await scan_repository_files(
        db,
        target_name=payload.target_name,
        repo_path=payload.repo_path,
        files=payload.files,
        auto_evaluate_controls=payload.auto_evaluate_controls,
        llm_router=llm_router,
        actor=actor,
    )
    base = ScanRunOut.model_validate(run)
    return ScanRunDetailOut(
        **base.model_dump(),
        findings=[ScanFindingOut.model_validate(f) for f in findings],
    )


@router.post("/probe-url", response_model=ScanRunDetailOut, status_code=status.HTTP_201_CREATED)
async def probe_url_endpoint(
    payload: UrlProbeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> ScanRunDetailOut:
    """Probe a live HTTP/HTTPS endpoint for TLS transport and security headers."""
    settings = resolve_settings(request)
    run, findings = await probe_live_url(
        db,
        target_name=payload.target_name,
        url=payload.url,
        auto_evaluate_controls=payload.auto_evaluate_controls,
        settings=settings,
        llm_router=llm_router,
        actor=actor,
    )
    base = ScanRunOut.model_validate(run)
    return ScanRunDetailOut(
        **base.model_dump(),
        findings=[ScanFindingOut.model_validate(f) for f in findings],
    )


@router.get("/schedules", response_model=list[ScheduledScanOut])
async def list_scheduled_scans(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[ScheduledScan]:
    """List recurring compliance drift scan schedules."""
    stmt = select(ScheduledScan).order_by(ScheduledScan.created_at.desc())
    return list((await db.execute(stmt)).scalars().all())


@router.post("/schedules", response_model=ScheduledScanOut, status_code=status.HTTP_201_CREATED)
async def create_scheduled_scan_endpoint(
    payload: ScheduledScanCreateRequest,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> ScheduledScan:
    """Register a recurring continuous compliance drift scan schedule."""
    return await create_scheduled_scan(db, payload=payload, actor=actor)


@router.post("/schedules/{schedule_id}/run", response_model=ScanRunOut)
async def run_scheduled_scan_endpoint(
    schedule_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> ScanRun:
    """Execute a specific scheduled compliance scan immediately."""
    settings = resolve_settings(request)
    sched = await get_schedule_or_404(db, schedule_id)
    _, run = await run_scheduled_scan(
        db,
        schedule=sched,
        settings=settings,
        llm_router=llm_router,
        actor=actor,
    )
    return run


@router.post("/schedules/run-due", response_model=list[ScanRunOut])
async def run_due_schedules_endpoint(
    request: Request,
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    actor: Actor = Depends(require_roles("compliance_officer", "admin")),
) -> list[ScanRun]:
    """Execute all active scheduled scans whose next_run_at window is due."""
    settings = resolve_settings(request)
    return await run_due_scheduled_scans(
        db,
        settings=settings,
        llm_router=llm_router,
        actor=actor,
    )
