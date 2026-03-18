from __future__ import annotations

from fastapi import APIRouter

from app.api.admin import router as admin_router
from app.api.auth import router as auth_router
from app.api.gateway import router as gateway_router, health, scan
from app.api.ops import router as ops_router, compare_evaluations


router = APIRouter()
router.include_router(auth_router)
router.include_router(gateway_router)
router.include_router(ops_router)
router.include_router(admin_router)

__all__ = ["router", "compare_evaluations", "scan", "health"]
