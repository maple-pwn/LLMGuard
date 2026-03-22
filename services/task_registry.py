from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import update
from sqlalchemy.orm import Session

from core.database import SessionLocal
from models.entities import TaskRun
from models.schemas import EvaluationRequest


def execute_task_payload(db: Session, task: TaskRun) -> tuple[dict[str, Any] | None, str | None]:
    payload = task.payload or {}

    if task.task_type == "evaluation":
        from services.evaluation import run_evaluation

        request = EvaluationRequest(**payload)
        run, metrics = run_evaluation(
            db,
            request,
            tenant_id=task.tenant_id,
            application_id=task.application_id,
            environment=task.environment,
        )
        return {"run_id": run.id, "metrics_keys": list(metrics.keys())}, run.report_path

    if task.task_type == "sample_audit":
        from services.sample_audit import audit_samples

        summary, report_path = audit_samples(db, tenant_id=task.tenant_id, application_id=task.application_id)
        return {"summary": summary}, report_path

    if task.task_type == "rule_effectiveness":
        from services.rule_analysis import analyze_rule_effectiveness

        rows, report_path = analyze_rule_effectiveness(db, run_id=payload.get("run_id"))
        return {"row_count": len(rows)}, report_path

    if task.task_type == "casebook":
        from services.casebook import build_casebook

        cases, report_path = build_casebook(
            db,
            run_id=payload.get("run_id"),
            owner=payload.get("owner", "security_ops"),
            tenant_id=task.tenant_id,
            application_id=task.application_id,
        )
        return {"case_count": len(cases)}, report_path

    if task.task_type == "weekly_report":
        from services.ops_reporting import generate_weekly_report

        report_path = generate_weekly_report(
            db,
            title=payload.get("title", "weekly_report"),
            tenant_id=task.tenant_id,
            application_id=task.application_id,
        )
        return {"title": payload.get("title", "weekly_report")}, report_path

    if task.task_type == "postmortem":
        from services.ops_reporting import generate_postmortem

        report_path = generate_postmortem(
            db,
            title=payload.get("title", "evaluation_postmortem"),
            run_id=payload.get("run_id"),
            tenant_id=task.tenant_id,
            application_id=task.application_id,
        )
        return {"run_id": payload.get("run_id")}, report_path

    raise ValueError(f"unsupported task type: {task.task_type}")


def append_task_log(task: TaskRun, level: str, message: str) -> None:
    log = list(task.execution_log or [])
    log.append({"at": datetime.now(UTC).isoformat(), "level": level, "message": message})
    task.execution_log = log[-100:]


def claim_task_for_execution(
    db: Session,
    task_id: int,
    *,
    allowed_statuses: tuple[str, ...],
) -> TaskRun | None:
    claimed_at = datetime.now(UTC)
    result = db.execute(
        update(TaskRun)
        .where(TaskRun.id == task_id, TaskRun.status.in_(allowed_statuses))
        .values(status="running", started_at=claimed_at, last_heartbeat_at=claimed_at, attempts=TaskRun.attempts + 1)
    )
    db.commit()
    if result.rowcount != 1:
        return None
    return db.query(TaskRun).filter(TaskRun.id == task_id).one()


def execute_task_record(db: Session, task: TaskRun) -> dict[str, Any]:
    if task.status == "completed":
        return task.result or {}
    append_task_log(task, "info", f"task attempt {task.attempts} started")
    db.add(task)
    db.commit()
    db.refresh(task)
    try:
        result, artifact_uri = execute_task_payload(db, task)
        task.status = "completed"
        task.result = result
        task.artifact_uri = artifact_uri
        task.error_message = None
        task.active_dedup_key = None
        task.finished_at = datetime.now(UTC)
        task.last_heartbeat_at = datetime.now(UTC)
        append_task_log(task, "info", "task completed")
        db.add(task)
        db.commit()
        return result or {}
    except Exception as exc:
        db.rollback()
        task = db.query(TaskRun).filter(TaskRun.id == task.id).one()
        append_task_log(task, "error", str(exc))
        task.error_message = str(exc)
        task.last_heartbeat_at = datetime.now(UTC)
        if task.attempts < task.max_retries:
            task.status = "retry_pending"
        else:
            task.status = "failed"
            task.active_dedup_key = None
            task.finished_at = datetime.now(UTC)
        db.add(task)
        db.commit()
        raise


def execute_task_by_id(task_id: int) -> dict[str, Any]:
    db = SessionLocal()
    try:
        task = db.query(TaskRun).filter(TaskRun.id == task_id).one_or_none()
        if task is None:
            raise ValueError("task not found")
        claimed = claim_task_for_execution(db, task_id, allowed_statuses=("queued", "pending_dispatch", "retry_pending"))
        if claimed is None:
            task = db.query(TaskRun).filter(TaskRun.id == task_id).one()
            if task.status == "completed":
                return task.result or {}
            return {"task_id": task.id, "status": task.status, "skipped": True}
        return execute_task_record(db, claimed)
    finally:
        db.close()
