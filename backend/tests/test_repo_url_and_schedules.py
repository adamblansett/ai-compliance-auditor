from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.core.auth import Actor
from app.core.config import Settings
from app.llm.router import LLMRouter
from app.scanners.repo_and_url import probe_live_url
from tests.conftest import AUDITOR_HEADERS, OFFICER_HEADERS, VIEWER_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_multi_file_repo_scan_and_schedules(tmp_path: Path) -> None:
    sample_repo = tmp_path / "sample_repo"
    (sample_repo / ".git").mkdir(parents=True)
    (sample_repo / ".git" / "config").write_text("DEBUG=true\n", encoding="utf-8")
    (sample_repo / "deploy").mkdir()
    (sample_repo / "deploy" / "staging.env").write_text(
        "DEBUG=true\nCORS_ORIGINS=*\n",
        encoding="utf-8",
    )
    (sample_repo / "infra").mkdir()
    (sample_repo / "infra" / "nginx.conf").write_text(
        "ssl_protocols TLSv1.3;\nencryption_at_rest=true\nkey_rotation=true\n",
        encoding="utf-8",
    )

    test_app = make_test_app(tmp_path)
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/v1/controls/seed-catalog", headers=AUDITOR_HEADERS)

        # Scan real directory (skips .git)
        dir_resp = await client.post(
            "/api/v1/scanners/scan-repo",
            headers=AUDITOR_HEADERS,
            json={"target_name": "local-repo", "repo_path": str(sample_repo)},
        )
        assert dir_resp.status_code == 201
        dir_data = dir_resp.json()
        assert dir_data["target_type"] == "repo_bundle"
        assert ".git" not in dir_data["artifact_preview"]
        assert dir_data["failed_checks"] >= 2

        # Scan inline multi-file bundle
        inline_resp = await client.post(
            "/api/v1/scanners/scan-repo",
            headers=AUDITOR_HEADERS,
            json={
                "target_name": "inline-bundle",
                "files": [
                    {
                        "path": "rbac/policy.json",
                        "content": '{"Action": "*", "mfa_required": false}',
                    },
                    {
                        "path": "docs/sop.md",
                        "content": "Incident response 72 hours DSAR retention schedule.",
                    },
                ],
            },
        )
        assert inline_resp.status_code == 201
        assert inline_resp.json()["failed_checks"] >= 2

        # Scheduled scan CRUD + manual run + run-due
        sched_resp = await client.post(
            "/api/v1/scanners/schedules",
            headers=AUDITOR_HEADERS,
            json={
                "name": "Hourly Preset Drift",
                "scan_mode": "preset",
                "target_ref": "hardened-prod-nginx",
                "target_type": "encryption",
                "interval_minutes": 60,
            },
        )
        assert sched_resp.status_code == 201
        sched_id = sched_resp.json()["id"]

        run_now = await client.post(
            f"/api/v1/scanners/schedules/{sched_id}/run",
            headers=AUDITOR_HEADERS,
        )
        assert run_now.status_code == 200
        assert run_now.json()["status"] == "passed"

        sched_list = await client.get("/api/v1/scanners/schedules", headers=VIEWER_HEADERS)
        assert sched_list.status_code == 200
        assert sched_list.json()[0]["last_scan_run_id"] == run_now.json()["id"]


@pytest.mark.asyncio
async def test_live_url_probe_ssrf_guard_and_headers(tmp_path: Path) -> None:
    test_app = make_test_app(tmp_path)
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        ssrf = await client.post(
            "/api/v1/scanners/probe-url",
            headers=AUDITOR_HEADERS,
            json={
                "target_name": "metadata-probe",
                "url": "http://169.254.169.254/latest/meta-data/",
            },
        )
        assert ssrf.status_code == 400

    # Test probe_live_url directly with MockTransport
    mock_transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            },
            text="ok",
        )
    )
    async with AsyncClient(transport=mock_transport) as mock_http:
        # Ensure DB initialized
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/api/v1/controls/seed-catalog", headers=OFFICER_HEADERS)

        async with test_app.state.session_factory() as session:
            run, findings = await probe_live_url(
                session,
                target_name="hardened-gateway",
                url="https://api.example.com/health",
                auto_evaluate_controls=True,
                settings=Settings(allow_private_url_probes=False),
                llm_router=LLMRouter(Settings()),
                actor=Actor(email="auditor@test.local", role="auditor", auth_method="test"),
                http_client=mock_http,
            )
            assert run.status == "passed"
            assert all(f.status == "pass" for f in findings)
