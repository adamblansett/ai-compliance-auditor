import io
import json
import zipfile

from app.db.models import EvidenceBundle
from app.evidence.chain import canonical_json
from app.evidence.pdf_report import render_bundle_attestation_pdf

STANDALONE_VERIFIER_SCRIPT = '''#!/usr/bin/env python3
"""Zero-dependency offline verifier for AI Compliance Auditor evidence packages."""

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import sys


def canonical_json(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def verify_directory(bundle_dir: Path, signing_key: str | None = None) -> int:
    manifest_path = bundle_dir / "manifest.json"
    sig_path = bundle_dir / "signature.json"
    if not manifest_path.exists():
        print(f"FAIL: missing {manifest_path}", file=sys.stderr)
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    actual_manifest_sha = hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest()

    chain = manifest.get("evidence_chain")
    if not isinstance(chain, list):
        print("FAIL: manifest.evidence_chain is missing or not a list", file=sys.stderr)
        return 1

    expected_prev = "GENESIS"
    expected_seq = 1
    last_hash = "GENESIS"
    for item in chain:
        if not isinstance(item, dict):
            print(f"FAIL: item #{expected_seq} is not an object", file=sys.stderr)
            return 1
        seq = item.get("item_seq")
        prev_hash = str(item.get("prev_hash", ""))
        item_type = str(item.get("item_type", ""))
        item_ref = str(item.get("item_ref", ""))
        payload = item.get("payload")
        item_hash = str(item.get("item_hash", ""))

        if seq != expected_seq or prev_hash != expected_prev:
            print(f"FAIL: chain linkage mismatch at item #{expected_seq}", file=sys.stderr)
            return 1
        recomputed = hashlib.sha256(
            canonical_json(
                {
                    "item_seq": expected_seq,
                    "item_type": item_type,
                    "item_ref": item_ref,
                    "payload": payload,
                    "prev_hash": prev_hash,
                }
            ).encode("utf-8")
        ).hexdigest()
        if item_hash != recomputed:
            print(
                f"FAIL: hash tamper detected at item #{expected_seq} ({item_ref})",
                file=sys.stderr,
            )
            return 1
        expected_prev = item_hash
        last_hash = item_hash
        expected_seq += 1

    if sig_path.exists():
        sig_meta = json.loads(sig_path.read_text(encoding="utf-8"))
        exp_manifest = sig_meta.get("manifest_sha256")
        exp_head = sig_meta.get("chain_head_hash")
        if exp_manifest and actual_manifest_sha != exp_manifest:
            print("FAIL: manifest_sha256 mismatch against signature.json", file=sys.stderr)
            return 1
        if exp_head and last_hash != exp_head:
            print("FAIL: chain_head_hash mismatch against signature.json", file=sys.stderr)
            return 1
        if signing_key:
            expected_hmac = hmac.new(
                signing_key.encode("utf-8"),
                f"{actual_manifest_sha}:{last_hash}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            actual_hmac = str(sig_meta.get("signature_hex", "")).strip().lower()
            if not actual_hmac or not hmac.compare_digest(actual_hmac, expected_hmac.lower()):
                print("FAIL: HMAC-SHA256 signature verification failed", file=sys.stderr)
                return 1
            print("HMAC-SHA256 signature verified.")

    print(
        f"PASS: Verified {len(chain)} chained evidence item(s). "
        f"manifest_sha256={actual_manifest_sha}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify exported compliance evidence bundle.")
    parser.add_argument("--dir", type=Path, default=Path("."), help="Extracted bundle directory")
    parser.add_argument("--signing-key", default=None, help="Optional HMAC signing key")
    args = parser.parse_args()
    return verify_directory(args.dir, signing_key=args.signing_key)


if __name__ == "__main__":
    raise SystemExit(main())
'''


def build_signed_bundle_zip(bundle: EvidenceBundle) -> bytes:
    """Package manifest JSON, HMAC signature metadata, PDF report, and CLI verifier."""
    manifest_bytes = json.dumps(bundle.manifest_json, indent=2, sort_keys=True).encode("utf-8")
    _ = canonical_json(bundle.manifest_json)

    sig_meta = {
        "bundle_id": bundle.id,
        "bundle_name": bundle.bundle_name,
        "status": bundle.status,
        "frameworks": list(bundle.frameworks_json or []),
        "period_start": bundle.period_start.isoformat(),
        "period_end": bundle.period_end.isoformat(),
        "chain_head_hash": bundle.chain_head_hash,
        "manifest_sha256": bundle.manifest_sha256,
        "signature_alg": bundle.signature_alg,
        "signature_key_id": bundle.signature_key_id,
        "signature_hex": bundle.signature_hex,
        "signed_at": bundle.signed_at.isoformat() if bundle.signed_at else None,
        "released_by": bundle.released_by,
        "released_at": bundle.released_at.isoformat() if bundle.released_at else None,
    }
    sig_bytes = json.dumps(sig_meta, indent=2).encode("utf-8")
    pdf_bytes = render_bundle_attestation_pdf(bundle)
    readme_txt = (
        "AI Compliance & Regulatory Auditor — Signed Evidence Package\n"
        "=============================================================\n\n"
        f"Bundle: {bundle.bundle_name} ({bundle.id})\n"
        f"Status: {bundle.status}\n"
        f"Manifest SHA-256: {bundle.manifest_sha256}\n"
        f"Chain Head SHA-256: {bundle.chain_head_hash}\n"
        f"Signature Key ID: {bundle.signature_key_id or 'unsigned'}\n\n"
        "Offline Verification:\n"
        "  python verify_bundle.py\n"
        "  python verify_bundle.py --signing-key <YOUR_SIGNING_KEY>\n"
    ).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("signature.json", sig_bytes)
        zf.writestr("attestation-report.pdf", pdf_bytes)
        zf.writestr("verify_bundle.py", STANDALONE_VERIFIER_SCRIPT.encode("utf-8"))
        zf.writestr("README_AUDITOR.txt", readme_txt)
    return buf.getvalue()
