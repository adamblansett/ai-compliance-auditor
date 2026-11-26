"""Optional Celery worker task bridge with inline async fallback."""

import asyncio
from typing import Any

from app.core.auth import Actor
from app.core.config import Settings, get_settings
from app.db.session import build_engine, build_session_factory
from app.llm.router import LLMRouter
from app.scanners.scheduler import get_schedule_or_404, run_due_scheduled_scans, run_scheduled_scan


async def _execute_schedule_async(schedule_id: str | None, settings: Settings) -> dict[str, Any]:
    engine = build_engine(settings.database_url)
    session_factory = build_session_factory(engine)
    llm_router = LLMRouter(settings)
    actor = Actor(
        email="scheduler-worker@acme-compliance.local",
        role="admin",
        auth_method="worker",
    )
    try:
        async with session_factory() as session:
            if schedule_id:
                sched = await get_schedule_or_404(session, schedule_id)
                _, run = await run_scheduled_scan(
                    session,
                    schedule=sched,
                    settings=settings,
                    llm_router=llm_router,
                    actor=actor,
                )
                return {"executed": 1, "scan_run_ids": [run.id]}
            runs = await run_due_scheduled_scans(
                session,
                settings=settings,
                llm_router=llm_router,
                actor=actor,
            )
            return {"executed": len(runs), "scan_run_ids": [r.id for r in runs]}
    finally:
        await engine.dispose()


def create_celery_app(settings: Settings | None = None) -> Any:
    """Create a Celery application when the optional 'worker' extra is installed."""
    from celery import Celery

    cfg = settings or get_settings()
    celery_app = Celery(
        "ai_compliance_auditor",
        broker=cfg.redis_url,
        backend=cfg.redis_url,
    )

    @celery_app.task(name="compliance.run_due_scans")
    def run_due_scans_task() -> dict[str, Any]:
        return asyncio.run(_execute_schedule_async(None, cfg))

    return celery_app


try:
    celery_app = create_celery_app()
except ImportError:
    celery_app = None
