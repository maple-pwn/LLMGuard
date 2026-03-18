from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from core.config import get_settings


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine_kwargs = {"future": True, "pool_pre_ping": not settings.database_url.startswith("sqlite")}
engine = create_engine(settings.database_url, connect_args=connect_args, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
Base = declarative_base()


def is_sqlite_database() -> bool:
    return engine.url.get_backend_name() == "sqlite"


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    if not is_sqlite_database():
        return
    from models import entities  # noqa: F401

    Base.metadata.create_all(bind=engine)
