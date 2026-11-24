from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import AUDITOR_HEADERS, VIEWER_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_all_five_scanner_collectors_and_pii_scrubbing(tmp_path: Path) -> None:
    test_app = make_test_app(tmp_path)
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/v1/controls/seed-catalog", headers=AUDITOR_HEADERS)

        presets = await client.get("/api/v1/scanners/presets", headers=VIEWER_HEADERS)
        assert presets.status_code == 200
        assert len(presets.json()) == 5

        # 1. Failing config
        cfg_fail = await client.post(
            "/api/v1/scanners/scan",
            headers=AUDITOR_HEADERS,
            json={
                "target_name": "bad-cfg",
                "target_type": "config",
                "artifact_filename": "bad.env",
                "content": (
                    "DEBUG=true\nCORS_ORIGINS=*\n"
                    "AUTH_SECRET_KEY=dev-insecure-secret-change-in-production-32bytes\n"
                    "SSL_VERIFY=false\n"
                ),
            },
        )
        assert cfg_fail.status_code == 201
        assert cfg_fail.json()["status"] == "failed"
        assert cfg_fail.json()["failed_checks"] == 4
        assert len(cfg_fail.json()["artifact_sha256"]) == 64

        # 2. Passing encryption
        enc_pass = await client.post(
            "/api/v1/scanners/scan",
            headers=AUDITOR_HEADERS,
            json={
                "target_name": "good-tls",
                "target_type": "encryption",
                "artifact_filename": "tls.conf",
                "content": (
                    "ssl_protocols TLSv1.3;\n"
                    "ssl_ciphers AES-256-GCM;\n"
                    "encryption_at_rest=true\n"
                    "key_rotation=true\n"
                ),
            },
        )
        assert enc_pass.status_code == 201
        assert enc_pass.json()["status"] == "passed"
        assert enc_pass.json()["passed_checks"] == 4

        # 3. Failing logging with raw PHI + SSN (must be scrubbed before DB storage!)
        raw_ssn = "123-45-6789"
        raw_mrn = "MRN-772190"
        log_fail = await client.post(
            "/api/v1/scanners/scan",
            headers=AUDITOR_HEADERS,
            json={
                "target_name": "phi-logs",
                "target_type": "logging",
                "artifact_filename": "app.log",
                "content": (
                    f"structlog x-request-id=abc log_retention_days=30 "
                    f"auth_event user ssn={raw_ssn} mrn={raw_mrn}"
                ),
            },
        )
        assert log_fail.status_code == 201
        log_data = log_fail.json()
        assert log_data["status"] == "failed"
        assert raw_ssn not in log_data["artifact_preview"]
        assert raw_mrn not in log_data["artifact_preview"]
        log002 = next(f for f in log_data["findings"] if f["rule_id"] == "LOG-002")
        assert log002["status"] == "fail"
        assert raw_ssn not in log002["evidence_snippet"]
        assert "[REDACTED_SSN]" in log002["evidence_snippet"]

        # 4. Failing RBAC
        rbac_fail = await client.post(
            "/api/v1/scanners/scan",
            headers=AUDITOR_HEADERS,
            json={
                "target_name": "iam-role",
                "target_type": "rbac",
                "artifact_filename": "iam.json",
                "content": '{"Action": "*", "mfa_required": false, "ttl_seconds": 999999}',
            },
        )
        assert rbac_fail.status_code == 201
        assert rbac_fail.json()["status"] == "failed"

        # 5. Passing SOP via multipart file upload
        sop_bytes = (
            b"Incident response 72 hours breach notification.\n"
            b"Data classification for PII and PHI.\n"
            b"Quarterly access review and offboarding.\n"
            b"DSAR and legal hold retention schedule.\n"
        )
        upload_resp = await client.post(
            "/api/v1/scanners/upload",
            headers=AUDITOR_HEADERS,
            data={"target_name": "sop-upload", "target_type": "sop"},
            files={"file": ("sop.md", sop_bytes, "text/markdown")},
        )
        assert upload_resp.status_code == 201
        assert upload_resp.json()["status"] == "passed"
        assert upload_resp.json()["passed_checks"] == 4

        runs_resp = await client.get("/api/v1/scanners/runs", headers=VIEWER_HEADERS)
        assert runs_resp.status_code == 200
        assert len(runs_resp.json()) == 5

        findings_resp = await client.get(
            "/api/v1/scanners/findings?status=fail", headers=VIEWER_HEADERS
        )
        assert findings_resp.status_code == 200
        assert len(findings_resp.json()) >= 7
