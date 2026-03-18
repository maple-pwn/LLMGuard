from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.admin import router as admin_router
from app.api.auth import router as auth_router
from app.api.gateway import router as gateway_router
from app.api.ops import router as ops_router
from core.bootstrap import bootstrap
from core.database import SessionLocal
from core.logging import setup_logging
from core.security import ensure_secure_api_keys, ensure_secure_jwt
from services.rule_engine import get_rule_engine


@asynccontextmanager
async def lifespan(_: FastAPI):
    setup_logging()
    ensure_secure_api_keys()
    ensure_secure_jwt()
    db = SessionLocal()
    try:
        bootstrap(db)
        get_rule_engine().reload_rules(db=db)
    finally:
        db.close()
    yield


app = FastAPI(title="LLM Firewall Gateway & Ops Platform", version="0.2.0", lifespan=lifespan)
app.include_router(auth_router)
app.include_router(gateway_router)
app.include_router(ops_router)
app.include_router(admin_router)
