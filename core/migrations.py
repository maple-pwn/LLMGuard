from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from core.database import engine


def _existing_columns(target_engine: Engine, table_name: str) -> set[str]:
    inspector = inspect(target_engine)
    if table_name not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def _add_missing_columns(target_engine: Engine, table_name: str, statements: Iterable[tuple[str, str]]) -> None:
    current_columns = _existing_columns(target_engine, table_name)
    with target_engine.begin() as connection:
        for column_name, ddl in statements:
            if column_name in current_columns:
                continue
            connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {ddl}"))


def _create_index_if_missing(target_engine: Engine, index_name: str, ddl: str) -> None:
    inspector = inspect(target_engine)
    existing = {index["name"] for index in inspector.get_indexes("task_runs")} if "task_runs" in inspector.get_table_names() else set()
    if index_name in existing:
        return
    with target_engine.begin() as connection:
        connection.execute(text(ddl))


def apply_sqlite_migrations(target_engine: Engine | None = None) -> None:
    active_engine = target_engine or engine
    if active_engine.url.get_backend_name() != "sqlite":
        return
    _add_missing_columns(
        active_engine,
        "samples",
        [
            ("tenant_id", "tenant_id INTEGER"),
            ("application_id", "application_id INTEGER"),
            ("label_confidence", "label_confidence FLOAT"),
            ("duplicate_group_id", "duplicate_group_id VARCHAR(64)"),
            ("boundary_sample_flag", "boundary_sample_flag BOOLEAN DEFAULT 0"),
            ("needs_review", "needs_review BOOLEAN DEFAULT 0"),
            ("review_comment", "review_comment TEXT"),
        ],
    )
    _add_missing_columns(
        active_engine,
        "rules",
        [
            ("rule_version", "rule_version VARCHAR(32) DEFAULT 'v1'"),
            ("created_by", "created_by VARCHAR(64)"),
            ("change_note", "change_note TEXT"),
        ],
    )
    _add_missing_columns(
        active_engine,
        "strategy_configs",
        [
            ("strategy_version", "strategy_version VARCHAR(32) DEFAULT 'v1'"),
            ("rule_selection", "rule_selection JSON"),
            ("output_filter_threshold", "output_filter_threshold FLOAT DEFAULT 0.8"),
        ],
    )
    _add_missing_columns(
        active_engine,
        "evaluation_runs",
        [
            ("tenant_id", "tenant_id INTEGER"),
            ("application_id", "application_id INTEGER"),
            ("environment", "environment VARCHAR(32)"),
        ],
    )
    _add_missing_columns(
        active_engine,
        "detection_results",
        [
            ("tenant_id", "tenant_id INTEGER"),
            ("application_id", "application_id INTEGER"),
            ("environment", "environment VARCHAR(32)"),
        ],
    )
    _add_missing_columns(
        active_engine,
        "task_runs",
        [
            ("queue_backend", "queue_backend VARCHAR(32) DEFAULT 'database'"),
            ("backend_job_id", "backend_job_id VARCHAR(128)"),
            ("idempotency_key", "idempotency_key VARCHAR(128)"),
            ("active_dedup_key", "active_dedup_key VARCHAR(128)"),
            ("attempts", "attempts INTEGER DEFAULT 0"),
            ("max_retries", "max_retries INTEGER DEFAULT 3"),
            ("timeout_seconds", "timeout_seconds INTEGER DEFAULT 300"),
            ("execution_log", "execution_log JSON"),
            ("last_heartbeat_at", "last_heartbeat_at DATETIME"),
        ],
    )
    _create_index_if_missing(
        active_engine,
        "ix_task_runs_active_dedup_key",
        "CREATE UNIQUE INDEX ix_task_runs_active_dedup_key ON task_runs (active_dedup_key)",
    )
    _add_missing_columns(
        active_engine,
        "case_records",
        [
            ("tenant_id", "tenant_id INTEGER"),
            ("application_id", "application_id INTEGER"),
        ],
    )
    _add_missing_columns(
        active_engine,
        "review_tasks",
        [
            ("tenant_id", "tenant_id INTEGER"),
            ("application_id", "application_id INTEGER"),
        ],
    )
    _add_missing_columns(
        active_engine,
        "audit_logs",
        [
            ("actor_user_id", "actor_user_id INTEGER"),
            ("object_type", "object_type VARCHAR(64)"),
            ("object_id", "object_id VARCHAR(64)"),
        ],
    )
