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
from app.db.models import PolicyDocument
from app.db.session import get_db
from app.llm.router import LLMRouter, get_llm_router
from app.rag.schemas import (
    PolicyCitationOut,
    PolicyDocumentCreateRequest,
    PolicyDocumentOut,
    RagQueryRequest,
    RagQueryResponse,
)
from app.rag.service import get_control_citations, ingest_policy_document, query_policy_rag

router = APIRouter(prefix="/rag", tags=["rag"])

_MAX_POLICY_BYTES = 2 * 1024 * 1024


@router.get("/documents", response_model=list[PolicyDocumentOut])
async def list_policy_documents(
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[PolicyDocument]:
    """List indexed policy and SOP documents."""
    stmt = select(PolicyDocument).order_by(PolicyDocument.created_at.desc())
    return list((await db.execute(stmt)).scalars().all())


@router.post(
    "/documents",
    response_model=PolicyDocumentOut,
    status_code=status.HTTP_201_CREATED,
)
async def ingest_policy_inline(
    payload: PolicyDocumentCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> PolicyDocument:
    """Ingest, PII-scrub, chunk, and embed an inline policy or SOP document."""
    settings = resolve_settings(request)
    raw_bytes = payload.content.encode("utf-8")
    return await ingest_policy_document(
        db,
        title=payload.title,
        filename=payload.filename,
        framework=payload.framework,
        version=payload.version,
        raw_bytes=raw_bytes,
        content=payload.content,
        settings=settings,
        actor=actor,
    )


@router.post(
    "/documents/upload",
    response_model=PolicyDocumentOut,
    status_code=status.HTTP_201_CREATED,
)
async def upload_policy_document(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(default=""),
    framework: str = Form(default="ALL"),
    version: str = Form(default="1.0"),
    db: AsyncSession = Depends(get_db),
    actor: Actor = Depends(require_roles("auditor", "compliance_officer", "admin")),
) -> PolicyDocument:
    """Upload a markdown/text policy or SOP file (<= 2 MiB) into the Policy RAG index."""
    raw_bytes = await file.read(_MAX_POLICY_BYTES + 1)
    if len(raw_bytes) > _MAX_POLICY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Uploaded policy file exceeds 2 MiB limit.",
        )
    if not raw_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded policy file is empty.",
        )

    settings = resolve_settings(request)
    filename = file.filename or "policy.md"
    resolved_title = title.strip() or filename
    text = raw_bytes.decode("utf-8", errors="replace")
    return await ingest_policy_document(
        db,
        title=resolved_title,
        filename=filename,
        framework=framework,
        version=version,
        raw_bytes=raw_bytes,
        content=text,
        settings=settings,
        actor=actor,
    )


@router.post("/query", response_model=RagQueryResponse)
async def query_policy_endpoint(
    payload: RagQueryRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    actor: Actor = Depends(get_current_actor),
) -> RagQueryResponse:
    """Query indexed policies and receive citation-grounded compliance guidance."""
    settings = resolve_settings(request)
    return await query_policy_rag(
        db,
        query=payload.query,
        framework=payload.framework,
        top_k=payload.top_k,
        llm_router=llm_router,
        settings=settings,
        actor=actor,
    )


@router.get("/controls/{control_code}/citations", response_model=list[PolicyCitationOut])
async def control_citations_endpoint(
    control_code: str,
    request: Request,
    top_k: int = Query(default=4, ge=1, le=12),
    db: AsyncSession = Depends(get_db),
    _: Actor = Depends(get_current_actor),
) -> list[PolicyCitationOut]:
    """Return top policy excerpts mapped or matched to a specific control code."""
    settings = resolve_settings(request)
    return await get_control_citations(
        db,
        control_code=control_code,
        top_k=top_k,
        settings=settings,
    )
