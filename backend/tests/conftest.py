from pathlib import Path
from typing import Any

from fastapi import FastAPI

from app.core.config import Settings
from app.main import create_app

OFFICER_HEADERS = {
    "X-Actor-Email": "officer@test.local",
    "X-Actor-Role": "compliance_officer",
}
AUDITOR_HEADERS = {
    "X-Actor-Email": "auditor@test.local",
    "X-Actor-Role": "auditor",
}
VIEWER_HEADERS = {
    "X-Actor-Email": "viewer@test.local",
    "X-Actor-Role": "viewer",
}


def make_test_app(tmp_path: Path, **overrides: Any) -> FastAPI:
    """Create an isolated FastAPI app backed by a per-test SQLite file."""
    db_file = tmp_path / "test_compliance_auditor.db"
    overrides.setdefault("rate_limit_enabled", False)
    cfg = Settings(
        database_url=f"sqlite+aiosqlite:///{db_file.as_posix()}",
        llm_default_provider="mock",
        auto_create_tables=True,
        seed_demo_data=False,
        **overrides,
    )
    return create_app(cfg)
