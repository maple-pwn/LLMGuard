from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.api.admin import create_policy_binding
from app.api.gateway import scan as gateway_scan
from core.bootstrap import bootstrap
from core.security import AuthContext
from models.entities import Application, PolicyBinding, Sample, TaskRun, Tenant
from models.schemas import PolicyBindingCreate, ScanRequest
from services.detection import resolve_gateway_strategy
from services.task_registry import claim_task_for_execution
from services.task_queue import TASK_TYPE_WEEKLY_REPORT, _claim_task_if_pending, claim_next_task, enqueue_task, process_task


def test_gateway_strategy_uses_policy_binding(phase2_db) -> None:
    tenant = Tenant(name="Tenant A", slug="tenant-a")
    phase2_db.add(tenant)
    phase2_db.commit()
    phase2_db.refresh(tenant)
    app = Application(tenant_id=tenant.id, name="Office Bot", app_key="office-bot", environment="prod")
    phase2_db.add(app)
    phase2_db.commit()
    phase2_db.refresh(app)
    phase2_db.add(
        PolicyBinding(
            tenant_id=tenant.id,
            application_id=app.id,
            environment="prod",
            scenario="office_assistant",
            strategy_name="full_stack_balanced_v2",
            rule_allowlist=["R001", "R002"],
            rule_blocklist=["R999"],
        )
    )
    phase2_db.commit()

    request = ScanRequest(
        user_input="帮我总结审批流程",
        scenario="office_assistant",
        session_id="s1",
        tenant_slug="tenant-a",
        application_key="office-bot",
        environment="prod",
    )
    strategy, resolved_tenant, resolved_app = resolve_gateway_strategy(phase2_db, request)

    assert strategy.name == "full_stack_balanced_v2"
    assert strategy.rule_selection is not None
    assert strategy.rule_selection["rule_ids"] == ["R001", "R002"]
    assert strategy.rule_selection["blocked_rule_ids"] == ["R999"]
    assert resolved_tenant is not None and resolved_tenant.slug == "tenant-a"
    assert resolved_app is not None and resolved_app.app_key == "office-bot"


def test_gateway_scan_fails_closed_without_binding(phase2_db) -> None:
    tenant = Tenant(name="Tenant B", slug="tenant-b")
    phase2_db.add(tenant)
    phase2_db.commit()
    phase2_db.refresh(tenant)
    app = Application(tenant_id=tenant.id, name="KB Bot", app_key="kb-bot", environment="prod")
    phase2_db.add(app)
    phase2_db.commit()

    with pytest.raises(HTTPException) as exc_info:
        gateway_scan(
            ScanRequest(
                user_input="帮我总结流程",
                scenario="office_assistant",
                session_id="s2",
                tenant_slug="tenant-b",
                application_key="kb-bot",
                environment="prod",
                strategy_name="rules_only",
            ),
            _=None,
            db=phase2_db,
        )
    assert exc_info.value.status_code == 403


def test_policy_binding_rejects_cross_tenant_application(phase2_db) -> None:
    tenant_a = Tenant(name="Tenant A", slug="tenant-a")
    tenant_b = Tenant(name="Tenant B", slug="tenant-b")
    phase2_db.add_all([tenant_a, tenant_b])
    phase2_db.commit()
    phase2_db.refresh(tenant_a)
    phase2_db.refresh(tenant_b)
    app = Application(tenant_id=tenant_b.id, name="Bot B", app_key="bot-b", environment="prod")
    phase2_db.add(app)
    phase2_db.commit()

    actor = AuthContext(
        user=type("UserStub", (), {"id": 1, "is_superuser": True})(),
        memberships=[],
        tenant_ids=set(),
        tenant_permissions={},
    )
    with pytest.raises(HTTPException) as exc_info:
        create_policy_binding(
            payload=PolicyBindingCreate(
                tenant_slug="tenant-a",
                application_key="bot-b",
                environment="prod",
                scenario="office_assistant",
                strategy_name="full_stack",
                rule_allowlist=[],
                rule_blocklist=[],
            ),
            actor=actor,
            db=phase2_db,
        )
    assert exc_info.value.status_code == 400


def test_claim_task_compare_and_set_prevents_double_claim(phase2_db) -> None:
    task = enqueue_task(phase2_db, TASK_TYPE_WEEKLY_REPORT, {"title": "weekly_pending"})
    other_session = sessionmaker(bind=phase2_db.get_bind(), expire_on_commit=False)()
    try:
        claimed = claim_next_task(other_session)
        assert claimed is not None and claimed.id == task.id
        assert _claim_task_if_pending(phase2_db, task.id, datetime.now(UTC)) is False
    finally:
        other_session.close()


def test_ops_task_queue_processes_weekly_report(phase2_db) -> None:
    phase2_db.add(Sample(text="测试样本", sample_type="benign", expected_result="allow", scenario="general_assistant"))
    phase2_db.commit()

    task = enqueue_task(phase2_db, TASK_TYPE_WEEKLY_REPORT, {"title": "weekly_async"})
    completed = process_task(phase2_db, task)

    assert completed.status == "completed"
    assert completed.artifact_uri is not None
    assert Path(completed.artifact_uri).exists()


def test_enqueue_task_persists_pending_status(phase2_db) -> None:
    task = enqueue_task(phase2_db, TASK_TYPE_WEEKLY_REPORT, {"title": "weekly_pending"})
    stored = phase2_db.query(TaskRun).filter(TaskRun.id == task.id).one()
    assert stored.status == "pending"


def test_enqueue_task_reuses_active_idempotent_job(phase2_db) -> None:
    first = enqueue_task(phase2_db, TASK_TYPE_WEEKLY_REPORT, {"title": "weekly_same"})
    second = enqueue_task(phase2_db, TASK_TYPE_WEEKLY_REPORT, {"title": "weekly_same"})
    assert first.id == second.id


def test_active_dedup_key_is_database_unique(phase2_db) -> None:
    phase2_db.add(TaskRun(task_type="weekly_report", status="pending", queue_backend="database", active_dedup_key="dup-key"))
    phase2_db.commit()
    phase2_db.add(TaskRun(task_type="weekly_report", status="pending", queue_backend="database", active_dedup_key="dup-key"))
    with pytest.raises(IntegrityError):
        phase2_db.commit()
    phase2_db.rollback()


def test_arq_claim_is_atomic_for_same_task(phase2_db) -> None:
    task = TaskRun(task_type="weekly_report", status="queued", queue_backend="arq", active_dedup_key="arq-dedup")
    phase2_db.add(task)
    phase2_db.commit()
    phase2_db.refresh(task)

    claimed = claim_task_for_execution(phase2_db, task.id, allowed_statuses=("queued", "pending_dispatch", "retry_pending"))
    skipped = claim_task_for_execution(phase2_db, task.id, allowed_statuses=("queued", "pending_dispatch", "retry_pending"))

    assert claimed is not None
    assert claimed.status == "running"
    assert claimed.attempts == 1
    assert skipped is None


def test_arq_enqueue_failure_marks_dispatch_failed_and_releases_dedup(phase2_db, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TASK_QUEUE_BACKEND", "arq")
    monkeypatch.setattr("services.task_queue.enqueue_arq_task_message_sync", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("redis down")))
    from core.config import get_settings

    get_settings.cache_clear()
    with pytest.raises(RuntimeError):
        enqueue_task(phase2_db, TASK_TYPE_WEEKLY_REPORT, {"title": "weekly_arq_fail"})
    task = phase2_db.query(TaskRun).order_by(TaskRun.id.desc()).first()
    assert task is not None
    assert task.status == "dispatch_failed"
    assert task.active_dedup_key is None
    assert "enqueue failed" in (task.error_message or "")
    monkeypatch.delenv("TASK_QUEUE_BACKEND", raising=False)
    get_settings.cache_clear()


def test_bootstrap_skips_schema_mutation_when_not_sqlite(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"init": 0, "migrate": 0}

    def fake_init() -> None:
        calls["init"] += 1

    def fake_migrate() -> None:
        calls["migrate"] += 1

    monkeypatch.setattr("core.bootstrap.is_sqlite_database", lambda: False)
    monkeypatch.setattr("core.bootstrap.init_db", fake_init)
    monkeypatch.setattr("core.bootstrap.apply_sqlite_migrations", fake_migrate)

    bootstrap()

    assert calls == {"init": 0, "migrate": 0}
