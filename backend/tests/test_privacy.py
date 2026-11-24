from datetime import date, timedelta
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
async def test_dsar_legal_hold_block_release_and_retention_exceptions(tmp_path: Path) -> None:
    test_app = make_test_app(tmp_path)
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Place legal hold for jane.doe@example.com
        hold_resp = await client.post(
            "/api/v1/privacy/legal-holds",
            headers=OFFICER_HEADERS,
            json={
                "title": "Litigation Hold Matter 77",
                "matter_reference": "LIT-2026-77",
                "custodian_scope": ["jane.doe@example.com"],
                "systems_scope": ["billing_ledger", "crm_postgres"],
                "reason": "Pending regulatory inquiry.",
            },
        )
        assert hold_resp.status_code == 201
        hold_id = hold_resp.json()["id"]
        hold_code = hold_resp.json()["hold_code"]

        # Create erasure DSAR matching custodian & system -> auto blocked
        dsar_resp = await client.post(
            "/api/v1/privacy/dsars",
            headers=AUDITOR_HEADERS,
            json={
                "request_type": "erasure",
                "regulation": "GDPR",
                "subject_email": "jane.doe@example.com",
                "data_systems": ["billing_ledger", "crm_postgres"],
                "notes": "Right to be forgotten request.",
            },
        )
        assert dsar_resp.status_code == 201
        dsar = dsar_resp.json()
        assert dsar["status"] == "blocked_by_legal_hold"
        assert dsar["legal_hold_blocked"] is True
        assert hold_code in dsar["blocking_hold_ids_json"]
        dsar_id = dsar["id"]

        # Preparing fulfillment must return 409 Conflict while hold is active
        blocked_prep = await client.post(
            f"/api/v1/privacy/dsars/{dsar_id}/prepare-fulfillment",
            headers=AUDITOR_HEADERS,
        )
        assert blocked_prep.status_code == 409
        assert hold_code in blocked_prep.json()["detail"]

        # Release legal hold -> DSAR unblocks
        release_resp = await client.post(
            f"/api/v1/privacy/legal-holds/{hold_id}/release",
            headers=OFFICER_HEADERS,
            json={"reason": "Inquiry closed without further preservation duty."},
        )
        assert release_resp.status_code == 200
        assert release_resp.json()["status"] == "released"

        # Now prepare fulfillment succeeds and creates HITL approval
        prep_ok = await client.post(
            f"/api/v1/privacy/dsars/{dsar_id}/prepare-fulfillment",
            headers=AUDITOR_HEADERS,
        )
        assert prep_ok.status_code == 200
        assert prep_ok.json()["status"] == "pending_approval"
        assert prep_ok.json()["export_package_sha256"] is not None
        dsar_approval_id = prep_ok.json()["approval_id"]

        # Approve DSAR fulfillment
        approve_dsar = await client.post(
            f"/api/v1/evidence/approvals/{dsar_approval_id}/decide",
            headers=OFFICER_HEADERS,
            json={"decision": "approved", "notes": "Erasure confirmed after hold release"},
        )
        assert approve_dsar.status_code == 200

        dsars_list = await client.get("/api/v1/privacy/dsars", headers=VIEWER_HEADERS)
        completed = next(d for d in dsars_list.json() if d["id"] == dsar_id)
        assert completed["status"] == "completed"
        assert completed["completed_at"] is not None

        # Retention policy violation & exception HITL approval
        pol_resp = await client.post(
            "/api/v1/privacy/retention-policies",
            headers=AUDITOR_HEADERS,
            json={
                "policy_code": "RET-TEST-1",
                "data_category": "Session Logs",
                "framework": "GDPR",
                "system_name": "analytics_warehouse",
                "retention_days": 90,
                "actual_oldest_record_days": 150,
                "purge_mechanism": "Partition drop",
                "encryption_at_rest": True,
            },
        )
        assert pol_resp.status_code == 201
        pol_id = pol_resp.json()["id"]
        assert pol_resp.json()["status"] == "violation_over_retained"

        verify_ret = await client.post(
            "/api/v1/privacy/retention-policies/verify",
            headers=AUDITOR_HEADERS,
        )
        assert verify_ret.status_code == 200
        assert verify_ret.json()[0]["status"] == "violation_over_retained"

        exc_resp = await client.post(
            f"/api/v1/privacy/retention-policies/{pol_id}/exceptions",
            headers=AUDITOR_HEADERS,
            json={
                "requested_retention_days": 180,
                "justification": "Migration window requires 180d history.",
                "expires_at": (date.today() + timedelta(days=45)).isoformat(),
            },
        )
        assert exc_resp.status_code == 201
        exc_approval_id = exc_resp.json()["approval_id"]

        approve_exc = await client.post(
            f"/api/v1/evidence/approvals/{exc_approval_id}/decide",
            headers=OFFICER_HEADERS,
            json={"decision": "approved", "notes": "Granted 45-day retention extension"},
        )
        assert approve_exc.status_code == 200

        policies_after = await client.get(
            "/api/v1/privacy/retention-policies", headers=VIEWER_HEADERS
        )
        assert policies_after.json()[0]["status"] == "exception_granted"
