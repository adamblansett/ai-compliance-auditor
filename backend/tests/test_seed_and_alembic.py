import sqlite3
from pathlib import Path

import pytest
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from alembic import command
from tests.conftest import OFFICER_HEADERS, VIEWER_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_demo_seed_idempotency_reset_and_overview(tmp_path: Path) -> None:
    test_app = make_test_app(tmp_path)
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post("/api/v1/seed/demo", headers=OFFICER_HEADERS)
        assert first.status_code == 200
        body = first.json()
        assert body["seeded"] is True
        assert body["controls_count"] == 18
        assert body["scan_runs_count"] == 5
        assert body["evidence_bundles_count"] == 1
        assert body["dsars_count"] == 3
        assert body["legal_holds_count"] == 1
        assert body["retention_policies_count"] == 4
        assert body["pending_approvals_count"] == 4

        second = await client.post("/api/v1/seed/demo", headers=OFFICER_HEADERS)
        assert second.status_code == 200
        assert second.json()["seeded"] is False

        reset = await client.post("/api/v1/seed/demo?reset=true", headers=OFFICER_HEADERS)
        assert reset.status_code == 200
        assert reset.json()["seeded"] is True
        assert reset.json()["pending_approvals_count"] == 4

        overview = await client.get("/api/v1/overview", headers=VIEWER_HEADERS)
        assert overview.status_code == 200
        ov = overview.json()
        assert ov["posture"]["total_controls"] == 18
        assert ov["scan_runs_count"] == 5
        assert ov["pending_approvals_count"] == 4
        assert ov["audit_chain"]["valid"] is True
        assert ov["dsar_metrics"]["legal_hold_blocked"] == 1
        assert ov["retention_metrics"]["violations"] == 1


def test_alembic_upgrade_and_downgrade_roundtrip(tmp_path: Path) -> None:
    backend_dir = Path(__file__).resolve().parents[1]
    db_path = tmp_path / "alembic_roundtrip.db"

    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path.as_posix()}")

    command.upgrade(cfg, "head")

    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    expected_tables = {
        "controls",
        "control_evaluations",
        "scan_runs",
        "scan_findings",
        "audit_events",
        "approval_requests",
        "evidence_bundles",
        "dsar_requests",
        "legal_holds",
        "retention_policies",
        "retention_exceptions",
    }
    assert expected_tables.issubset(tables)

    command.downgrade(cfg, "base")
    with sqlite3.connect(db_path) as conn:
        remaining = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert not (expected_tables & remaining)

    command.upgrade(cfg, "head")
    with sqlite3.connect(db_path) as conn:
        restored = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert expected_tables.issubset(restored)
