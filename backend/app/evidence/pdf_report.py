import textwrap
from typing import Any

from app.db.models import EvidenceBundle


def _escape_pdf_text(text: str) -> str:
    sanitized = text.encode("latin-1", errors="replace").decode("latin-1")
    return sanitized.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_lines(lines: list[tuple[str, bool]], width: int = 86) -> list[tuple[str, bool]]:
    wrapped: list[tuple[str, bool]] = []
    for raw_line, is_bold in lines:
        if not raw_line:
            wrapped.append(("", False))
            continue
        chunks = textwrap.wrap(raw_line, width=width, break_long_words=True) or [""]
        for chunk in chunks:
            wrapped.append((chunk, is_bold))
    return wrapped


def render_bundle_attestation_pdf(bundle: EvidenceBundle) -> bytes:
    """Render a multi-page PDF-1.4 executive attestation report for an evidence bundle."""
    manifest: dict[str, Any] = dict(bundle.manifest_json or {})
    summary: dict[str, Any] = dict(manifest.get("summary") or {})
    chain_items: list[dict[str, Any]] = list(manifest.get("evidence_chain") or [])

    raw_lines: list[tuple[str, bool]] = [
        ("AI COMPLIANCE & REGULATORY AUDITOR — AUDIT ATTESTATION REPORT", True),
        ("", False),
        (f"Bundle Name: {bundle.bundle_name}", True),
        (f"Bundle ID: {bundle.id}", False),
        (f"Frameworks: {', '.join(bundle.frameworks_json or [])}", False),
        (
            f"Audit Period: {bundle.period_start.isoformat()} to {bundle.period_end.isoformat()}",
            False,
        ),
        (f"Approval Status: {bundle.status}", False),
        (f"Compiled By: {bundle.compiled_by}", False),
        (f"Released By: {bundle.released_by or 'Pending Compliance Officer Release'}", False),
        ("", False),
        ("EXECUTIVE SUMMARY", True),
        (
            f"Controls: {summary.get('controls_count', 0)} total | "
            f"{summary.get('passing_controls', 0)} passing | "
            f"{summary.get('failing_controls', 0)} failing",
            False,
        ),
        (
            f"Scans & Findings: {summary.get('scan_runs_count', 0)} scan runs | "
            f"{summary.get('findings_count', 0)} findings",
            False,
        ),
        (
            f"Privacy & Retention: {summary.get('dsar_count', 0)} DSARs | "
            f"{summary.get('active_legal_holds', 0)} active legal holds | "
            f"{summary.get('retention_policies_count', 0)} retention policies",
            False,
        ),
        ("", False),
        ("CRYPTOGRAPHIC INTEGRITY & SIGNATURE", True),
        (f"Evidence Chain Items: {bundle.item_count}", False),
        (f"Chain Head SHA-256: {bundle.chain_head_hash}", False),
        (f"Manifest SHA-256:   {bundle.manifest_sha256}", False),
        (
            f"Signature Alg / Key: {bundle.signature_alg or 'unsigned'} / "
            f"{bundle.signature_key_id or 'none'}",
            False,
        ),
        (f"Signature Digest:   {bundle.signature_hex or 'none'}", False),
        ("", False),
        ("AI ATTESTATION COMMENTARY", True),
        (bundle.ai_attestation_summary or "No summary recorded.", False),
        ("", False),
        ("CHAINED EVIDENCE INDEX", True),
    ]

    for item in chain_items[:120]:
        seq = item.get("item_seq", "?")
        itype = item.get("item_type", "")
        iref = item.get("item_ref", "")
        ihash = str(item.get("item_hash", ""))[:20]
        raw_lines.append((f"#{seq:03} | {itype} | {iref} | sha256:{ihash}...", False))

    if len(chain_items) > 120:
        omitted = len(chain_items) - 120
        raw_lines.append(
            (f"... ({omitted} additional items omitted from PDF; see manifest.json)", False)
        )

    lines = _wrap_lines(raw_lines, width=86)
    lines_per_page = 48
    pages = [lines[i : i + lines_per_page] for i in range(0, len(lines), lines_per_page)] or [[]]

    # PDF objects:
    # 1: Catalog, 2: Pages, 3: F1 Helvetica, 4: F2 Helvetica-Bold,
    # then for each page: Page obj + Content stream obj
    objects: list[bytes] = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"",  # placeholder for Pages object
        b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n",
    ]

    page_obj_ids: list[int] = []
    next_id = 5
    for page_lines in pages:
        page_id = next_id
        content_id = next_id + 1
        next_id += 2
        page_obj_ids.append(page_id)

        ops: list[str] = ["BT", "50 755 Td"]
        for idx, (text_val, is_bold) in enumerate(page_lines):
            font = "/F2" if is_bold else "/F1"
            size = "11" if is_bold else "9.5"
            if idx > 0:
                ops.append("0 -14 Td")
            ops.append(f"{font} {size} Tf ({_escape_pdf_text(text_val)}) Tj")
        ops.append("ET")
        stream_bytes = "\n".join(ops).encode("latin-1", errors="replace")

        page_obj = (
            f"{page_id} 0 obj\n"
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            f"/Contents {content_id} 0 R >>\nendobj\n"
        ).encode("latin-1")
        content_obj = (
            f"{content_id} 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin-1")
            + stream_bytes
            + b"\nendstream\nendobj\n"
        )
        objects.append(page_obj)
        objects.append(content_obj)

    kids_str = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objects[1] = (
        f"2 0 obj\n<< /Type /Pages /Kids [{kids_str}] /Count {len(page_obj_ids)} >>\nendobj\n"
    ).encode("latin-1")

    buf = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = [0]
    for obj in objects:
        offsets.append(len(buf))
        buf.extend(obj)

    xref_pos = len(buf)
    buf.extend(f"xref\n0 {len(offsets)}\n".encode("latin-1"))
    buf.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        buf.extend(f"{off:010d} 00000 n \n".encode("latin-1"))

    buf.extend(
        (
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode("latin-1")
    )
    return bytes(buf)
