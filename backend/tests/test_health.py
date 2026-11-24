from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import Settings
from app.main import app, create_app
from tests.conftest import make_test_app


@pytest.mark.asyncio
async def test_health_and_readiness_endpoints() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for path in ("/api/v1/health", "/api/v1/health/live", "/api/v1/health/ready"):
            response = await client.get(path)
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert data["service"] == "ai-compliance-auditor"
            assert data["app_name"] == "AI Compliance & Regulatory Auditor"
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"


def test_production_security_validation_rejects_default_secret() -> None:
    insecure = Settings(app_env="production")
    with pytest.raises(RuntimeError, match="AUTH_SECRET_KEY"):
        create_app(insecure)


def test_production_security_validation_rejects_wildcard_cors() -> None:
    insecure = Settings(
        app_env="production",
        auth_secret_key="a-very-secure-production-key-at-least-32-bytes-long",
        cors_origins="*",
    )
    with pytest.raises(RuntimeError, match="CORS_ORIGINS"):
        create_app(insecure)


@pytest.mark.asyncio
async def test_auth_bearer_token_and_role_enforcement(tmp_path: Path) -> None:
    test_app = make_test_app(tmp_path, auth_require_token=True)
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        unauth = await client.get("/api/v1/auth/me")
        assert unauth.status_code == 401

        tok_resp = await client.post(
            "/api/v1/auth/token",
            json={"email": "auditor@acme.org", "role": "auditor"},
        )
        assert tok_resp.status_code == 200
        token = tok_resp.json()["access_token"]

        me_resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_resp.status_code == 200
        assert me_resp.json()["email"] == "auditor@acme.org"
        assert me_resp.json()["role"] == "auditor"
        assert me_resp.json()["auth_method"] == "bearer_token"

        forbidden = await client.post(
            "/api/v1/seed/demo",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert forbidden.status_code == 403


@pytest.mark.asyncio
async def test_dev_token_endpoint_blocked_in_production(tmp_path: Path) -> None:
    prod_db = tmp_path / "prod.db"
    prod_cfg = Settings(
        app_env="production",
        auth_secret_key="production-secret-key-with-more-than-32-bytes-entropy",
        cors_origins="https://compliance.acme.org",
        database_url=f"sqlite+aiosqlite:///{prod_db.as_posix()}",
    )
    prod_app = create_app(prod_cfg)
    transport = ASGITransport(app=prod_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/token",
            json={"email": "admin@acme.org", "role": "admin"},
        )
        assert resp.status_code == 403
