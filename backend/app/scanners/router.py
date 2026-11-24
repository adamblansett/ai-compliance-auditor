from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, get_current_actor, require_roles
from app.db.models import ScanFinding, ScanRun
from app.db.session import get_db
from app.llm.router import LLMRouter, get_llm_router
from app.scanners.collectors import SCANNER_PRESETS
from app.scanners.engine import execute_scan
from app.scanners.schemas import (
    ScanFindingOut,
    ScannerPresetOut,
    ScanRequest,
    ScanRunDetailOut,
    ScanRunOut,
    TargetType,
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
