from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import (
    AUDITOR_HEADERS,
    OFFICER_HEADERS,
    VIEWER_HEADERS,
    make_test_app,
)


@pytest.mark.asyncio
async def test_controls_catalog_custom_evaluation_and_waiver(tmp_path: Path) -> None:
    test_app = make_test_app(tmp_path)
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        seed_resp = await client.post("/api/v1/controls/seed-catalog", headers=AUDITOR_HEADERS)
        assert seed_resp.status_code == 200
        assert seed_resp.json()["created"] == 18
        assert seed_resp.json()["total"] == 18

        controls_resp = await client.get("/api/v1/controls", headers=VIEWER_HEADERS)
        assert controls_resp.status_code == 200
        controls = controls_resp.json()
        assert len(controls) == 18

        custom_resp = await client.post(
            "/api/v1/controls",
            headers=AUDITOR_HEADERS,
            json={
                "control_code": "SOC2-CC9.9",
                "framework": "SOC2",
                "category": "Custom Security",
                "title": "Custom Production Config Check",
                "description": "Require disabled debug mode and valid CORS.",
                "severity": "high",
                "scanner_domains": ["config"],
                "required_rules": ["CFG-001", "CFG-002"],
                "owner_email": "sec@test.local",
                "remediation_guidance": "Fix staging config flags.",
            },
        )
        assert custom_resp.status_code == 201
        custom_id = custom_resp.json()["id"]

        scan_resp = await client.post(
            "/api/v1/scanners/scan",
            headers=AUDITOR_HEADERS,
            json={
                "target_name": "prod-env",
                "target_type": "config",
                "artifact_filename": "prod.env",
                "content": (
                    "APP_ENV=production\nDEBUG=false\n"
                    "CORS_ORIGINS=https://app.example.com\n"
                    "AUTH_SECRET_KEY=vault:prod/secret\nX-Frame-Options: DENY\n"
                ),
                "auto_evaluate_controls": True,
            },
        )
        assert scan_resp.status_code == 201

        soc2_resp = await client.get(
            "/api/v1/controls?framework=SOC2",
            headers=VIEWER_HEADERS,
        )
        assert soc2_resp.status_code == 200
        custom_ctrl = next(c for c in soc2_resp.json() if c["id"] == custom_id)
        assert custom_ctrl["status"] == "passing"
        assert custom_ctrl["compliance_score"] == 100.0

        eval_hist = await client.get(
            f"/api/v1/controls/{custom_id}/evaluations",
            headers=VIEWER_HEADERS,
        )
        assert eval_hist.status_code == 200
        assert len(eval_hist.json()) >= 1

        # Create failing scan for CFG-001 and test HITL waiver + RBAC enforcement
        fail_scan = await client.post(
            "/api/v1/scanners/scan",
            headers=AUDITOR_HEADERS,
            json={
                "target_name": "staging-env",
                "target_type": "config",
                "artifact_filename": "staging.env",
                "content": "DEBUG=true\nCORS_ORIGINS=*\n",
                "auto_evaluate_controls": True,
            },
        )
        assert fail_scan.status_code == 201

        posture_resp = await client.get("/api/v1/controls/posture", headers=VIEWER_HEADERS)
        assert posture_resp.status_code == 200
        assert posture_resp.json()["total_controls"] == 19

        waiver_req = await client.post(
            f"/api/v1/controls/{custom_id}/waiver",
            headers=AUDITOR_HEADERS,
            json={"justification": "Temporary staging exception", "waiver_days": 15},
        )
        assert waiver_req.status_code == 200
        approval_id = waiver_req.json()["approval_id"]

        # Auditor cannot decide approvals (403)
        denied = await client.post(
            f"/api/v1/evidence/approvals/{approval_id}/decide",
            headers=AUDITOR_HEADERS,
            json={"decision": "approved", "notes": "self approve"},
        )
        assert denied.status_code == 403

        # Compliance officer approves waiver
        approved = await client.post(
            f"/api/v1/evidence/approvals/{approval_id}/decide",
            headers=OFFICER_HEADERS,
            json={"decision": "approved", "notes": "Approved for 15 days"},
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"

        updated_ctrls = await client.get("/api/v1/controls?status=waived", headers=VIEWER_HEADERS)
        assert any(c["id"] == custom_id for c in updated_ctrls.json())
