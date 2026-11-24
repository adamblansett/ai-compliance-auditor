from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Actor, require_roles, resolve_settings
from app.db.session import get_db
from app.llm.router import LLMRouter, get_llm_router
from app.seed.demo_data import SeedSummaryOut, seed_demo_dataset

router = APIRouter(prefix="/seed", tags=["seed"])


@router.post("/demo", response_model=SeedSummaryOut)
async def seed_demo_endpoint(
    request: Request,
    reset: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
    llm_router: LLMRouter = Depends(get_llm_router),
    actor: Actor = Depends(require_roles("compliance_officer", "admin")),
) -> SeedSummaryOut:
    """Seed (or reset and re-seed) the realistic compliance auditor demo dataset."""
    settings = resolve_settings(request)
    return await seed_demo_dataset(
        db,
        llm_router=llm_router,
        settings=settings,
        actor=actor,
        reset=reset,
    )
