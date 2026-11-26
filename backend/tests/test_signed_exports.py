import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import AUDITOR_HEADERS, VIEWER_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_signed_zip_pdf_and_offline_cli_verifier(tmp_path: Path) -> None:
    signing_key = "test-signing-key-with-at-least-32-bytes"
    test_app = make_test_app(tmp_path, bundle_signing_key=signing_key)
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/v1/controls/seed-catalog", headers=AUDITOR_HEADERS)
        await client.post(
            "/api/v1/scanners/scan",
            headers=AUDITOR_HEADERS,
            json={
                "target_name": "prod-tls",
                "target_type": "encryption",
                "artifact_filename": "tls.conf",
                "content": "ssl_protocols TLSv1.3;\nencryption_at_rest=true\nkey_rotation=true\n",
            },
        )

        compiled = await client.post(
            "/api/v1/evidence/bundles/compile",
            headers=AUDITOR_HEADERS,
            json={"bundle_name": "Signed Export Audit", "frameworks": ["SOC2"]},
        )
        assert compiled.status_code == 201
        bundle = compiled.json()
        bundle_id = bundle["id"]
        assert bundle["signature_alg"] == "HMAC-SHA256"
        assert bundle["signature_key_id"].startswith("hmac-")
        assert len(bundle["signature_hex"]) == 64

        pdf_resp = await client.get(
            f"/api/v1/evidence/bundles/{bundle_id}/report.pdf",
            headers=VIEWER_HEADERS,
        )
        assert pdf_resp.status_code == 200
        assert pdf_resp.headers["content-type"] == "application/pdf"
        assert pdf_resp.content.startswith(b"%PDF-1.4")
        assert b"%%EOF" in pdf_resp.content[-64:]

        zip_resp = await client.get(
            f"/api/v1/evidence/bundles/{bundle_id}/export-zip",
            headers=VIEWER_HEADERS,
        )
        assert zip_resp.status_code == 200
        assert zip_resp.headers["content-type"] == "application/zip"

    zip_path = tmp_path / "bundle.zip"
    zip_path.write_bytes(zip_resp.content)
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
        assert {
            "manifest.json",
            "signature.json",
            "attestation-report.pdf",
            "verify_bundle.py",
            "README_AUDITOR.txt",
        }.issubset(names)
        zf.extractall(extract_dir)

    verifier_script = extract_dir / "verify_bundle.py"
    ok_proc = subprocess.run(
        [
            sys.executable,
            str(verifier_script),
            "--dir",
            str(extract_dir),
            "--signing-key",
            signing_key,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok_proc.returncode == 0
    assert "HMAC-SHA256 signature verified." in ok_proc.stdout
    assert "PASS:" in ok_proc.stdout

    # Wrong signing key fails verification
    bad_key_proc = subprocess.run(
        [
            sys.executable,
            str(verifier_script),
            "--dir",
            str(extract_dir),
            "--signing-key",
            "wrong-signing-key",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad_key_proc.returncode == 1

    # Tamper 1 byte in manifest.json -> offline verifier rejects it
    manifest_file = extract_dir / "manifest.json"
    manifest_text = manifest_file.read_text(encoding="utf-8")
    manifest_file.write_text(
        manifest_text.replace("Signed Export Audit", "Signed Export Audit!"),
        encoding="utf-8",
    )
    tamper_proc = subprocess.run(
        [sys.executable, str(verifier_script), "--dir", str(extract_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert tamper_proc.returncode == 1
