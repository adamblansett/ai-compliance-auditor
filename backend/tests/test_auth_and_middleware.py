from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import VIEWER_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_user_registration_login_refresh_and_rbac(tmp_path: Path) -> None:
    test_app = make_test_app(tmp_path, auth_require_token=True)
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Initial bootstrap user registration succeeds without prior auth
        reg_admin = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "admin@acme.org",
                "full_name": "Admin User",
                "password": "StrongPassword!123",
                "role": "admin",
                "mfa_enabled": True,
            },
        )
        assert reg_admin.status_code == 201
        admin_token = reg_admin.json()["access_token"]
        refresh_token = reg_admin.json()["refresh_token"]

        # Subsequent registration requires admin token
        reg_unauth = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "auditor@acme.org",
                "full_name": "Auditor",
                "password": "StrongPassword!123",
                "role": "auditor",
            },
        )
        assert reg_unauth.status_code == 401

        reg_auditor = await client.post(
            "/api/v1/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "email": "auditor@acme.org",
                "full_name": "Auditor",
                "password": "StrongPassword!123",
                "role": "auditor",
            },
        )
        assert reg_auditor.status_code == 201

        # Wrong password rejected
        bad_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "auditor@acme.org", "password": "wrong-password"},
        )
        assert bad_login.status_code == 401

        # Valid login + refresh
        good_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "auditor@acme.org", "password": "StrongPassword!123"},
        )
        assert good_login.status_code == 200
        assert good_login.json()["actor"]["role"] == "auditor"

        refreshed = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["actor"]["email"] == "admin@acme.org"

        users_list = await client.get(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert users_list.status_code == 200
        assert len(users_list.json()) == 2
        assert "password_hash" not in users_list.json()[0]


@pytest.mark.asyncio
async def test_rate_limit_and_telemetry_middleware(tmp_path: Path) -> None:
    test_app = make_test_app(
        tmp_path,
        rate_limit_enabled=True,
        rate_limit_requests_per_minute=3,
        otel_enabled=True,
    )
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for _ in range(3):
            ok = await client.get("/api/v1/controls", headers=VIEWER_HEADERS)
            assert ok.status_code == 200
            assert "x-trace-id" in ok.headers
            assert ok.headers["x-ratelimit-limit"] == "3"

        limited = await client.get("/api/v1/controls", headers=VIEWER_HEADERS)
        assert limited.status_code == 429
        assert "retry-after" in limited.headers

        # Health endpoints bypass rate limiting
        health = await client.get("/api/v1/health/live")
        assert health.status_code == 200
