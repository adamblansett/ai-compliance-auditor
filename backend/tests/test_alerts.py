from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.alerts.service import evaluate_drift_alerts
from app.core.auth import Actor
from tests.conftest import AUDITOR_HEADERS, OFFICER_HEADERS, VIEWER_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_drift_alerts_dedup_lifecycle_and_signed_webhooks(tmp_path: Path) -> None:
    test_app = make_test_app(tmp_path)
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/v1/controls/seed-catalog", headers=AUDITOR_HEADERS)

        # Fail config controls and create overdue DSAR to trigger alerts
        await client.post(
            "/api/v1/scanners/scan",
            headers=AUDITOR_HEADERS,
            json={
                "target_name": "bad-prod-cfg",
                "target_type": "config",
                "artifact_filename": "prod.env",
                "content": "DEBUG=true\nCORS_ORIGINS=*\nAUTH_SECRET_KEY=changeme\n",
                "auto_evaluate_controls": True,
            },
        )
        await client.post(
            "/api/v1/privacy/dsars",
            headers=AUDITOR_HEADERS,
            json={
                "request_type": "access",
                "regulation": "GDPR",
                "subject_email": "overdue@example.com",
                "due_date": (date.today() - timedelta(days=2)).isoformat(),
                "data_systems": ["crm_postgres"],
            },
        )

        # Register signed webhook (SSRF rejected first)
        bad_hook = await client.post(
            "/api/v1/alerts/webhooks",
            headers=OFFICER_HEADERS,
            json={
                "name": "Bad SSRF",
                "target_url": "http://169.254.169.254/hook",
                "event_types": [],
            },
        )
        assert bad_hook.status_code == 400

        hook_resp = await client.post(
            "/api/v1/alerts/webhooks",
            headers=OFFICER_HEADERS,
            json={
                "name": "SecOps Webhook",
                "target_url": "https://hooks.example.com/compliance",
                "event_types": ["control_regression", "dsar_overdue"],
                "secret_hmac": "webhook-hmac-secret",
            },
        )
        assert hook_resp.status_code == 201

    delivered: list[dict[str, str]] = []

    def _capture_webhook(request: httpx.Request) -> httpx.Response:
        delivered.append(
            {
                "sig": request.headers.get("X-Auditor-Signature", ""),
                "event": request.headers.get("X-Auditor-Event", ""),
                "body": request.content.decode("utf-8"),
            }
        )
        return httpx.Response(200, json={"received": True})

    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(_capture_webhook)) as mock_http,
        test_app.state.session_factory() as session,
    ):
        opened = await evaluate_drift_alerts(
            session,
            actor=Actor(email="officer@test.local", role="compliance_officer", auth_method="test"),
            http_client=mock_http,
        )
        assert len(opened) >= 2
        assert len(delivered) >= 2
        assert all(d["sig"].startswith("sha256=") for d in delivered)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Second evaluation deduplicates existing open alerts
        second = await client.post("/api/v1/alerts/evaluate", headers=AUDITOR_HEADERS)
        assert second.status_code == 200
        assert len(second.json()) == 0

        all_alerts = await client.get("/api/v1/alerts", headers=VIEWER_HEADERS)
        assert all_alerts.status_code == 200
        first_id = all_alerts.json()[0]["id"]

        ack = await client.post(
            f"/api/v1/alerts/{first_id}/acknowledge",
            headers=AUDITOR_HEADERS,
        )
        assert ack.status_code == 200
        assert ack.json()["status"] == "acknowledged"

        res = await client.post(
            f"/api/v1/alerts/{first_id}/resolve",
            headers=OFFICER_HEADERS,
        )
        assert res.status_code == 200
        assert res.json()["status"] == "resolved"
