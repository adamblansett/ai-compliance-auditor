import copy
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.db.models import AuditEvent
from tests.conftest import (
    AUDITOR_HEADERS,
    OFFICER_HEADERS,
    VIEWER_HEADERS,
    make_test_app,
)


@pytest.mark.asyncio
async def test_evidence_bundle_compile_verify_tamper_and_sod(tmp_path: Path) -> None:
    test_app = make_test_app(tmp_path, enforce_separation_of_duties=True)
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

        # Auditor compiles evidence bundle
        compile_resp = await client.post(
            "/api/v1/evidence/bundles/compile",
            headers=AUDITOR_HEADERS,
            json={
                "bundle_name": "SOC2 Q4 Audit Export",
                "frameworks": ["SOC2", "HIPAA"],
            },
        )
        assert compile_resp.status_code == 201
        bundle = compile_resp.json()
        assert bundle["status"] == "pending_approval"
        assert bundle["item_count"] > 0
        bundle_id = bundle["id"]
        approval_id = bundle["approval_id"]

        # Separation of duties blocks self-approval even if requester uses officer role
        same_user_headers = {
            "X-Actor-Email": AUDITOR_HEADERS["X-Actor-Email"],
            "X-Actor-Role": "compliance_officer",
        }
        sod_fail = await client.post(
            f"/api/v1/evidence/approvals/{approval_id}/decide",
            headers=same_user_headers,
            json={"decision": "approved", "notes": "self approve"},
        )
        assert sod_fail.status_code == 403

        # Different officer approves bundle release
        release_ok = await client.post(
            f"/api/v1/evidence/approvals/{approval_id}/decide",
            headers=OFFICER_HEADERS,
            json={"decision": "approved", "notes": "Verified for external auditor"},
        )
        assert release_ok.status_code == 200
        assert release_ok.json()["status"] == "approved"

        # Verify stored bundle by ID
        verify_ok = await client.get(
            f"/api/v1/evidence/bundles/{bundle_id}/verify",
            headers=VIEWER_HEADERS,
        )
        assert verify_ok.status_code == 200
        assert verify_ok.json()["valid"] is True

        # Export bundle and verify standalone payload
        export_resp = await client.get(
            f"/api/v1/evidence/bundles/{bundle_id}/export",
            headers=VIEWER_HEADERS,
        )
        assert export_resp.status_code == 200
        exported = export_resp.json()
        assert exported["status"] == "approved_released"

        verify_payload_ok = await client.post(
            "/api/v1/evidence/bundles/verify-payload",
            headers=VIEWER_HEADERS,
            json={
                "manifest": exported["manifest"],
                "expected_manifest_sha256": exported["manifest_sha256"],
                "expected_chain_head": exported["chain_head_hash"],
            },
        )
        assert verify_payload_ok.status_code == 200
        assert verify_payload_ok.json()["valid"] is True

        # Tamper 1 character in exported manifest payload and verify detection
        tampered = copy.deepcopy(exported["manifest"])
        tampered["evidence_chain"][0]["payload"]["title"] = (
            str(tampered["evidence_chain"][0]["payload"].get("title", "x")) + "!"
        )
        verify_tamper = await client.post(
            "/api/v1/evidence/bundles/verify-payload",
            headers=VIEWER_HEADERS,
            json={
                "manifest": tampered,
                "expected_manifest_sha256": exported["manifest_sha256"],
            },
        )
        assert verify_tamper.status_code == 200
        assert verify_tamper.json()["valid"] is False
        assert verify_tamper.json()["broken_item_seq"] == 1

        # Audit chain is intact prior to DB tamper
        chain_ok = await client.get("/api/v1/evidence/audit-events/verify", headers=VIEWER_HEADERS)
        assert chain_ok.status_code == 200
        assert chain_ok.json()["valid"] is True
        assert chain_ok.json()["total_events"] >= 4

    # Simulate direct DB tampering on audit_events and verify chain detects exact sequence
    async with test_app.state.session_factory() as session:
        ev = (
            await session.execute(select(AuditEvent).where(AuditEvent.sequence_no == 2))
        ).scalar_one()
        ev.action = "tampered_action"
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        chain_bad = await client.get("/api/v1/evidence/audit-events/verify", headers=VIEWER_HEADERS)
        assert chain_bad.status_code == 200
        assert chain_bad.json()["valid"] is False
        assert chain_bad.json()["broken_sequence_no"] == 2
