from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.config import get_settings
from core.database import SessionLocal
from core.privacy import fingerprint_text
from core.queue import enqueue_arq_task_message_sync, get_queue_info, is_arq_backend
from models.entities import TaskRun
from services.task_registry import append_task_log, execute_task_by_id, execute_task_record


TASK_TYPE_EVALUATION = "evaluation"
TASK_TYPE_SAMPLE_AUDIT = "sample_audit"
TASK_TYPE_RULE_EFFECTIVENESS = "rule_effectiveness"
TASK_TYPE_CASEBOOK = "casebook"
TASK_TYPE_WEEKLY_REPORT = "weekly_report"
TASK_TYPE_POSTMORTEM = "postmortem"
ACTIVE_TASK_STATUSES = ("pending", "pending_dispatch", "queued", "running", "retry_pending")
TERMINAL_TASK_STATUSES = ("completed", "failed", "dispatch_failed")


def _build_idempotency_key(
    task_type: str,
    payload: dict[str, Any] | None,
    tenant_id: int | None,
    application_id: int | None,
    environment: str | None,
) -> str:
    payload_repr = repr(sorted((payload or {}).items()))
    basis = f"{task_type}|{tenant_id}|{application_id}|{environment}|{payload_repr}"
    return fingerprint_text(basis) or basis


def enqueue_task(
    db: Session,
    task_type: str,
    payload: dict[str, Any] | None = None,
    *,
    tenant_id: int | None = None,
    application_id: int | None = None,
    environment: str | None = None,
    requested_by: str | None = None,
    idempotency_key: str | None = None,
) -> TaskRun:
    queue_info = get_queue_info()
    dedupe_key = idempotency_key or _build_idempotency_key(task_type, payload, tenant_id, application_id, environment)
    existing = (
        db.query(TaskRun)
        .filter(TaskRun.active_dedup_key == dedupe_key, TaskRun.status.in_(ACTIVE_TASK_STATUSES))
        .order_by(TaskRun.id.desc())
        .first()
    )
    if existing is not None:
        return existing

    initial_status = "pending_dispatch" if is_arq_backend() else "pending"
    settings = get_settings()
    task = TaskRun(
        task_type=task_type,
        status=initial_status,
        queue_backend=queue_info.backend,
        idempotency_key=dedupe_key,
        active_dedup_key=dedupe_key,
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        payload=payload or {},
        requested_by=requested_by,
        max_retries=settings.task_max_retries,
        timeout_seconds=settings.task_timeout_seconds,
        execution_log=[],
    )
    append_task_log(task, "info", f"task created with backend={queue_info.backend}")
    db.add(task)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(TaskRun)
            .filter(TaskRun.active_dedup_key == dedupe_key, TaskRun.status.in_(ACTIVE_TASK_STATUSES))
            .order_by(TaskRun.id.desc())
            .first()
        )
        if existing is not None:
            return existing
        raise
    db.refresh(task)

    if queue_info.backend == "arq":
        try:
            job_id = enqueue_arq_task_message_sync(task.id, job_id=f"{queue_info.queue_name}:{task.id}")
            task.backend_job_id = job_id
            task.status = "queued"
            append_task_log(task, "info", f"task enqueued to redis broker job_id={job_id}")
            db.add(task)
            db.commit()
            db.refresh(task)
        except Exception as exc:
            db.rollback()
            task = db.query(TaskRun).filter(TaskRun.id == task.id).one()
            task.status = "dispatch_failed"
            task.error_message = f"enqueue failed: {exc}"
            task.active_dedup_key = None
            task.finished_at = datetime.now(UTC)
            append_task_log(task, "error", f"enqueue failed: {exc}")
            db.add(task)
            db.commit()
            db.refresh(task)
            raise
    return task


def get_task(db: Session, task_id: int) -> TaskRun | None:
    return db.query(TaskRun).filter(TaskRun.id == task_id).one_or_none()


def list_tasks(db: Session, status: str | None = None, limit: int = 100) -> list[TaskRun]:
    query = db.query(TaskRun)
    if status:
        query = query.filter(TaskRun.status == status)
    return query.order_by(TaskRun.id.desc()).limit(limit).all()


def _claim_task_if_pending(db: Session, task_id: int, started_at: datetime | None = None) -> bool:
    claim_started_at = started_at or datetime.now(UTC)
    result = db.execute(
        update(TaskRun)
        .where(TaskRun.id == task_id, TaskRun.status.in_(["pending", "retry_pending"]))
        .values(status="running", started_at=claim_started_at, last_heartbeat_at=claim_started_at, attempts=TaskRun.attempts + 1)
    )
    db.commit()
    return result.rowcount == 1


def claim_next_task(db: Session) -> TaskRun | None:
    # Database fallback mode only. Redis/Arq workers claim tasks via the broker.
    while True:
        task_id = (
            db.query(TaskRun.id)
            .filter(TaskRun.queue_backend == "database", TaskRun.status.in_(["pending", "retry_pending"]))
            .order_by(TaskRun.id.asc())
            .limit(1)
            .scalar()
        )
        if task_id is None:
            return None
        if _claim_task_if_pending(db, task_id):
            return db.query(TaskRun).filter(TaskRun.id == task_id).one()


def process_task(db: Session, task: TaskRun) -> TaskRun:
    try:
        if task.queue_backend == "database":
            execute_task_record(db, task)
        else:
            execute_task_by_id(task.id)
    except Exception:
        pass
    refreshed = db.query(TaskRun).filter(TaskRun.id == task.id).one()
    if refreshed.status == "retry_pending" and refreshed.queue_backend == "arq":
        refreshed.status = "queued"
        refreshed.backend_job_id = enqueue_arq_task_message_sync(refreshed.id, job_id=f"{get_queue_info().queue_name}:{refreshed.id}:retry:{refreshed.attempts}")
        db.add(refreshed)
        db.commit()
        db.refresh(refreshed)
    return refreshed


def run_one_pending_task() -> TaskRun | None:
    db = SessionLocal()
    try:
        if is_arq_backend():
            raise RuntimeError("run_one_pending_task is only valid for the database queue backend")
        task = claim_next_task(db)
        if task is None:
            return None
        return process_task(db, task)
    finally:
        db.close()
