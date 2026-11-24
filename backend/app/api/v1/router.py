from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.overview import router as overview_router
from app.controls.router import router as controls_router
from app.evidence.router import router as evidence_router
from app.privacy.router import router as privacy_router
from app.scanners.router import router as scanners_router
from app.seed.router import router as seed_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(overview_router)
api_v1_router.include_router(controls_router)
api_v1_router.include_router(scanners_router)
api_v1_router.include_router(evidence_router)
api_v1_router.include_router(privacy_router)
api_v1_router.include_router(seed_router)
