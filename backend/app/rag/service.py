import hashlib
import re

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.controls.evaluator import ensure_default_controls
from app.core.auth import Actor
from app.core.config import Settings
from app.db.models import Control, PolicyChunk, PolicyDocument
from app.evidence.chain import record_audit_event
from app.llm.pii import redact_pii
from app.llm.router import LLMRouter
from app.rag.embeddings import cosine_similarity, get_embedder
from app.rag.schemas import PolicyCitationOut, RagQueryResponse

_HEADING_RE = re.compile(r"^\s{0,3}(#{1,4})\s+(.+)$")


def chunk_policy_text(
    text: str,
    *,
    max_chars: int = 700,
    overlap: int = 100,
) -> list[tuple[str, str]]:
    """Split a policy/SOP document into heading-tagged overlapping text chunks."""
    sections: list[tuple[str, list[str]]] = []
    current_heading = "Overview"
    current_lines: list[str] = []

    for line in text.splitlines():
        m = _HEADING_RE.match(line)
        if m:
            if any(ln.strip() for ln in current_lines):
                sections.append((current_heading, current_lines))
            current_heading = m.group(2).strip()[:200]
            current_lines = []
        else:
            current_lines.append(line)

    if any(ln.strip() for ln in current_lines):
        sections.append((current_heading, current_lines))

    chunks: list[tuple[str, str]] = []
    for heading, lines in sections:
        section_text = "\n".join(lines).strip()
        if not section_text:
            continue
        if len(section_text) <= max_chars:
            chunks.append((heading, section_text))
            continue

        start = 0
        while start < len(section_text):
            end = min(len(section_text), start + max_chars)
            piece = section_text[start:end].strip()
            if piece:
                chunks.append((heading, piece))
            if end >= len(section_text):
                break
            start = max(start + 1, end - overlap)

    return chunks


async def ingest_policy_document(
    db: AsyncSession,
    *,
    title: str,
    filename: str,
    framework: str,
    version: str,
    raw_bytes: bytes,
    content: str,
    settings: Settings,
    actor: Actor,
) -> PolicyDocument:
    """Scrub PII/PHI, chunk, embed, auto-map controls, and index a policy document."""
    doc_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    redaction = redact_pii(content)
    scrubbed_text = redaction.redacted_text
    raw_chunks = chunk_policy_text(scrubbed_text)
    if not raw_chunks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy document produced no indexable text chunks.",
        )

    controls = list((await db.execute(select(Control))).scalars().all())
    if not controls:
        await ensure_default_controls(db)
        controls = list((await db.execute(select(Control))).scalars().all())

    embedder = get_embedder(settings)
    control_vectors: list[tuple[Control, list[float]]] = []
    for ctrl in controls:
        ctrl_text = f"{ctrl.control_code} {ctrl.framework} {ctrl.title} {ctrl.description}"
        control_vectors.append((ctrl, await embedder.embed(ctrl_text)))

    doc = PolicyDocument(
        title=title.strip(),
        filename=filename.strip() or "policy.md",
        framework=framework.strip().upper(),
        version=version.strip() or "1.0",
        document_sha256=doc_sha256,
        pii_redaction_count=redaction.total_redactions,
        chunk_count=len(raw_chunks),
        uploaded_by=actor.email,
    )
    db.add(doc)
    await db.flush()

    for idx, (heading, chunk_text) in enumerate(raw_chunks):
        vec = await embedder.embed(f"{heading}\n{chunk_text}")
        scored_controls: list[tuple[float, str]] = []
        for ctrl, cvec in control_vectors:
            if doc.framework != "ALL" and ctrl.framework != doc.framework:
                continue
            sim = cosine_similarity(vec, cvec)
            if sim >= 0.08:
                scored_controls.append((sim, ctrl.control_code))
        scored_controls.sort(reverse=True)
        mapped = [code for _, code in scored_controls[:3]]

        db.add(
            PolicyChunk(
                document_id=doc.id,
                chunk_index=idx,
                section_heading=heading,
                content=chunk_text,
                embedding_json=vec,
                mapped_controls_json=mapped,
            )
        )

    await db.flush()
    await record_audit_event(
        db,
        event_type="rag.document_ingested",
        actor=actor,
        entity_type="policy_document",
        entity_id=doc.id,
        action="ingest_policy",
        details={
            "title": doc.title,
            "framework": doc.framework,
            "chunk_count": len(raw_chunks),
            "pii_redaction_count": redaction.total_redactions,
            "document_sha256": doc_sha256,
        },
    )
    await db.commit()
    await db.refresh(doc)
    return doc


async def query_policy_rag(
    db: AsyncSession,
    *,
    query: str,
    framework: str | None,
    top_k: int,
    llm_router: LLMRouter,
    settings: Settings,
    actor: Actor,
) -> RagQueryResponse:
    """Retrieve top policy citations via vector similarity and synthesize grounded answer."""
    _ = actor
    scrubbed_query = redact_pii(query.strip())
    embedder = get_embedder(settings)
    query_vec = await embedder.embed(scrubbed_query.redacted_text)

    stmt = select(PolicyChunk, PolicyDocument).join(
        PolicyDocument, PolicyChunk.document_id == PolicyDocument.id
    )
    if framework and framework.strip().upper() != "ALL":
        fw = framework.strip().upper()
        stmt = stmt.where(PolicyDocument.framework.in_([fw, "ALL"]))

    rows = list((await db.execute(stmt)).all())
    scored: list[tuple[float, PolicyChunk, PolicyDocument]] = []
    for chunk, doc in rows:
        sim = cosine_similarity(query_vec, list(chunk.embedding_json or []))
        scored.append((sim, chunk, doc))

    scored.sort(key=lambda item: item[0], reverse=True)
    top_hits = scored[:top_k]

    citations = [
        PolicyCitationOut(
            chunk_id=chunk.id,
            document_id=doc.id,
            document_title=doc.title,
            framework=doc.framework,
            section_heading=chunk.section_heading,
            chunk_index=chunk.chunk_index,
            score=score,
            mapped_controls=list(chunk.mapped_controls_json or []),
            excerpt=chunk.content[:320],
        )
        for score, chunk, doc in top_hits
    ]

    if not citations:
        return RagQueryResponse(
            query=scrubbed_query.redacted_text,
            answer="No indexed policy documents matched your query. Upload a policy or SOP first.",
            llm_provider="none",
            pii_redacted=scrubbed_query.total_redactions > 0,
            citations=[],
        )

    context_block = "\n".join(
        f"[{idx}] {c.document_title} ({c.section_heading}): {c.excerpt}"
        for idx, c in enumerate(citations, start=1)
    )
    prompt = f"Question: {scrubbed_query.redacted_text}\nCitations:\n{context_block}"
    ai_res = await llm_router.generate(
        prompt=prompt,
        system_prompt=(
            "Answer compliance questions using only the provided internal policy citations."
        ),
        task_type="policy_rag",
    )

    return RagQueryResponse(
        query=scrubbed_query.redacted_text,
        answer=ai_res.content,
        llm_provider=ai_res.provider,
        pii_redacted=ai_res.pii_redacted or scrubbed_query.total_redactions > 0,
        citations=citations,
    )


async def get_control_citations(
    db: AsyncSession,
    *,
    control_code: str,
    top_k: int,
    settings: Settings,
) -> list[PolicyCitationOut]:
    """Return top policy document excerpts mapped or semantically matched to a control."""
    norm_code = control_code.strip().upper()
    control = (
        await db.execute(select(Control).where(Control.control_code == norm_code))
    ).scalar_one_or_none()
    if control is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Control '{control_code}' not found.",
        )

    embedder = get_embedder(settings)
    ctrl_vec = await embedder.embed(
        f"{control.control_code} {control.framework} {control.title} {control.description}"
    )

    rows = list(
        (
            await db.execute(
                select(PolicyChunk, PolicyDocument).join(
                    PolicyDocument, PolicyChunk.document_id == PolicyDocument.id
                )
            )
        ).all()
    )
    scored: list[tuple[float, PolicyChunk, PolicyDocument]] = []
    for chunk, doc in rows:
        sim = cosine_similarity(ctrl_vec, list(chunk.embedding_json or []))
        mapped = list(chunk.mapped_controls_json or [])
        if norm_code in mapped:
            sim = round(min(1.0, sim + 0.2), 4)
        scored.append((sim, chunk, doc))

    scored.sort(key=lambda item: item[0], reverse=True)
    return [
        PolicyCitationOut(
            chunk_id=chunk.id,
            document_id=doc.id,
            document_title=doc.title,
            framework=doc.framework,
            section_heading=chunk.section_heading,
            chunk_index=chunk.chunk_index,
            score=score,
            mapped_controls=list(chunk.mapped_controls_json or []),
            excerpt=chunk.content[:320],
        )
        for score, chunk, doc in scored[:top_k]
    ]
