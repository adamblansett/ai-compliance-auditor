import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, get_current_actor, require_roles, resolve_settings
from app.db.models import ApprovalRequest, AuditEvent, EvidenceBundle
from app.db.session import get_db
from app.evidence.approvals import decide_approval
from app.evidence.chain import verify_audit_chain, verify_evidence_bundle_manifest
from app.evidence.compiler import compile_evidence_bundle
from app.evidence.packager import build_signed_bundle_zip
from app.evidence.pdf_report import render_bundle_attestation_pdf
from app.evidence.schemas import (
    ApprovalDecisionRequest,
    ApprovalRequestOut,
    AuditChainVerifyOut,
    AuditEventOut,
    BundleCompileRequest,
    BundleVerifyOut,
    BundleVerifyPayloadRequest,
    EvidenceBundleDetailOut,
    EvidenceBundleExportOut,
    EvidenceBundleOut,
    PiiRedactRequest,
    PiiRedactResponse,
)
from app.llm.pii import redact_pii
from app.llm.router import LLMRouter, get_llm_router

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("/bundles", response_model=list[EvidenceBundleOut])
async def list_bundles(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[EvidenceBundle]:
    """List compiled audit evidence bundles newest first."""
    stmt = select(EvidenceBundle).order_by(EvidenceBundle.created_at.desc())
    return list((await db.execute(stmt)).scalars().all())


@router.post(
    "/bundles/compile",
    response_model=EvidenceBundleDetailOut,
    status_code=status.HTTP_201_CREATED,
)
async def compile_bundle_endpoint(
    payload: BundleCompileRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> EvidenceBundle:
    """Compile a tamper-evident hash-chained evidence bundle and queue HITL approval."""
    settings = resolve_settings(request)
    return await compile_evidence_bundle(
        db,
        bundle_name=payload.bundle_name,
        frameworks=list(payload.frameworks),
        period_start=payload.period_start,
        period_end=payload.period_end,
        llm_router=llm_router,
        actor=actor,
        signing_key=settings.effective_signing_key,
    )


@router.post("/bundles/verify-payload", response_model=BundleVerifyOut)
async def verify_bundle_payload(
    payload: BundleVerifyPayloadRequest,
    _: Actor = Depends(get_current_actor),
) -> BundleVerifyOut:
    """Independently verify any exported bundle manifest JSON against SHA-256 links."""
    return verify_evidence_bundle_manifest(
        payload.manifest,
        expected_manifest_sha256=payload.expected_manifest_sha256,
        expected_chain_head=payload.expected_chain_head,
    )


@router.get("/bundles/{bundle_id}", response_model=EvidenceBundleDetailOut)
async def get_bundle_detail(
    bundle_id: str,
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> EvidenceBundle:
    """Retrieve a single evidence bundle including its full hash-chained manifest."""
    bundle = await db.get(EvidenceBundle, bundle_id)
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence bundle '{bundle_id}' not found.",
        )
    return bundle


@router.get("/bundles/{bundle_id}/verify", response_model=BundleVerifyOut)
async def verify_bundle_by_id(
    bundle_id: str,
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> BundleVerifyOut:
    """Verify hash-chain and manifest SHA-256 integrity of a stored evidence bundle."""
    bundle = await db.get(EvidenceBundle, bundle_id)
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence bundle '{bundle_id}' not found.",
        )
    return verify_evidence_bundle_manifest(
        bundle.manifest_json,
        expected_manifest_sha256=bundle.manifest_sha256,
        expected_chain_head=bundle.chain_head_hash,
    )


@router.get("/bundles/{bundle_id}/export", response_model=EvidenceBundleExportOut)
async def export_bundle(
    bundle_id: str,
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> EvidenceBundleExportOut:
    """Export an evidence bundle JSON package for external auditors or independent verification."""
    bundle = await db.get(EvidenceBundle, bundle_id)
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence bundle '{bundle_id}' not found.",
        )
    return EvidenceBundleExportOut(
        bundle_id=bundle.id,
        bundle_name=bundle.bundle_name,
        status=bundle.status,
        chain_head_hash=bundle.chain_head_hash,
        manifest_sha256=bundle.manifest_sha256,
        signature_alg=bundle.signature_alg,
        signature_key_id=bundle.signature_key_id,
        signature_hex=bundle.signature_hex,
        manifest=bundle.manifest_json,
    )


def _safe_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "evidence-bundle"


@router.get("/bundles/{bundle_id}/report.pdf")
async def download_bundle_pdf(
    bundle_id: str,
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> Response:
    """Download an executive PDF attestation report for an evidence bundle."""
    bundle = await db.get(EvidenceBundle, bundle_id)
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence bundle '{bundle_id}' not found.",
        )
    pdf_bytes = render_bundle_attestation_pdf(bundle)
    slug = _safe_slug(bundle.bundle_name)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{slug}-attestation.pdf"'},
    )


@router.get("/bundles/{bundle_id}/export-zip")
async def download_bundle_zip(
    bundle_id: str,
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> Response:
    """Download a signed auditor ZIP package with manifest, PDF report, and CLI verifier."""
    bundle = await db.get(EvidenceBundle, bundle_id)
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence bundle '{bundle_id}' not found.",
        )
    zip_bytes = build_signed_bundle_zip(bundle)
    slug = _safe_slug(bundle.bundle_name)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{slug}-signed.zip"'},
    )


@router.get("/audit-events", response_model=list[AuditEventOut])
async def list_audit_events(
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[AuditEvent]:
    """List immutable audit trail events in reverse chronological sequence order."""
    stmt = select(AuditEvent).order_by(AuditEvent.sequence_no.desc()).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


@router.get("/audit-events/verify", response_model=AuditChainVerifyOut)
async def verify_audit_events_endpoint(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> AuditChainVerifyOut:
    """Verify full SHA-256 hash chain integrity across all audit events."""
    return await verify_audit_chain(db)


@router.get("/approvals", response_model=list[ApprovalRequestOut])
async def list_approvals(
    status_filter: str | None = Query(default=None, alias="status"),
    entity_type: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[ApprovalRequest]:
    """List HITL approval requests with optional status and entity_type filters."""
    stmt = select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc())
    if status_filter:
        stmt = stmt.where(ApprovalRequest.status == status_filter.strip().lower())
    if entity_type:
        stmt = stmt.where(ApprovalRequest.entity_type == entity_type.strip().lower())
    return list((await db.execute(stmt)).scalars().all())


@router.post("/approvals/{approval_id}/decide", response_model=ApprovalRequestOut)
async def decide_approval_endpoint(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("compliance_officer", "admin")),
) -> ApprovalRequest:
    """Approve or reject a pending HITL compliance gate."""
    settings = resolve_settings(request)
    return await decide_approval(
        db,
        approval_id=approval_id,
        decision=payload.decision,
        notes=payload.notes,
        actor=actor,
        settings=settings,
    )


@router.post("/pii/redact", response_model=PiiRedactResponse)
async def redact_pii_endpoint(
    payload: PiiRedactRequest,
    _: Actor = Depends(get_current_actor),
) -> PiiRedactResponse:
    """Run the compliance PII/PHI/PCI/secret scrubber on sample text."""
    res = redact_pii(payload.text)
    return PiiRedactResponse(
        redacted_text=res.redacted_text,
        findings=res.findings,
        total_redactions=res.total_redactions,
    )
