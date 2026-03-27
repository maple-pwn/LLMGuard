from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.config import get_settings
from core.database import Base
from core.migrations import apply_sqlite_migrations


os.environ["SCAN_API_KEY"] = "test-scan-key"
os.environ["ADMIN_API_KEY"] = "test-admin-key"
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-for-phase2"
get_settings.cache_clear()


@pytest.fixture
def phase2_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("REPORT_DIR", str(tmp_path / "reports"))
    get_settings.cache_clear()
    settings = get_settings()
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    (settings.report_dir.parent / "cases").mkdir(parents=True, exist_ok=True)
    (settings.report_dir.parent / "weekly_reports").mkdir(parents=True, exist_ok=True)
    (settings.report_dir.parent / "postmortems").mkdir(parents=True, exist_ok=True)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    apply_sqlite_migrations(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        get_settings.cache_clear()
