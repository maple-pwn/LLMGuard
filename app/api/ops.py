from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import ValidationError
from sqlalchemy.orm import Session

from core.database import get_db
from core.security import AuthContext, ensure_actor_can_access_tenant, ensure_actor_has_tenant_permission, require_permission
from models.entities import Application, CaseRecord, EvaluationRun, ReviewTask, Sample, TaskRun, Tenant
from models.schemas import (
    CaseBuildRequest,
    CaseRead,
    EvaluationRequest,
    PostmortemRequest,
    ReviewTaskCreate,
    ReviewTaskRead,
    SampleReviewQueueItem,
    StrategyCompareRequest,
    TaskRunRead,
    TaskSubmissionResponse,
    WeeklyReportRequest,
)
from services.audit_log import record_audit_event
from services.casebook import list_cases
from services.compare import compare_evaluation_runs
from services.sample_audit import sample_audit_tips
from services.task_queue import (
    TASK_TYPE_CASEBOOK,
    TASK_TYPE_EVALUATION,
    TASK_TYPE_POSTMORTEM,
    TASK_TYPE_RULE_EFFECTIVENESS,
    TASK_TYPE_SAMPLE_AUDIT,
    TASK_TYPE_WEEKLY_REPORT,
    enqueue_task,
    get_task,
    list_tasks,
)


router = APIRouter(prefix="/ops", tags=["ops"])


def _resolve_scope(
    db: Session,
    actor: AuthContext,
    *,
    permission: str,
    tenant_slug: str | None = None,
    application_key: str | None = None,
    environment: str | None = None,
    run_id: int | None = None,
) -> tuple[int | None, int | None, str | None]:
    tenant_id: int | None = None
    application_id: int | None = None
    resolved_environment = environment

    if run_id is not None:
        run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).one_or_none()
        if run is None:
            raise HTTPException(status_code=404, detail="evaluation run not found")
        ensure_actor_can_access_tenant(actor, run.tenant_id)
        ensure_actor_has_tenant_permission(actor, run.tenant_id, permission)
        tenant_id = run.tenant_id
        application_id = run.application_id
        resolved_environment = run.environment or resolved_environment

    tenant = None
    if tenant_slug is not None:
        tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).one_or_none()
        if tenant is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        ensure_actor_can_access_tenant(actor, tenant.id)
        ensure_actor_has_tenant_permission(actor, tenant.id, permission)
        tenant_id = tenant.id

    if application_key is not None:
        application = db.query(Application).filter(Application.app_key == application_key).one_or_none()
        if application is None:
            raise HTTPException(status_code=404, detail="application not found")
        ensure_actor_can_access_tenant(actor, application.tenant_id)
        ensure_actor_has_tenant_permission(actor, application.tenant_id, permission)
        if tenant_id is not None and application.tenant_id != tenant_id:
            raise HTTPException(status_code=400, detail="application does not belong to tenant")
        tenant_id = application.tenant_id
        application_id = application.id
        resolved_environment = application.environment or resolved_environment

    if not actor.is_superuser and tenant_id is None:
        visible = actor.visible_tenant_ids(permission)
        if len(visible) == 1:
            tenant_id = next(iter(visible))
        else:
            raise HTTPException(status_code=400, detail="tenant scope is required")

    return tenant_id, application_id, resolved_environment


@router.post("/evaluations", response_model=TaskSubmissionResponse)
def submit_evaluation(
    payload: EvaluationRequest,
    actor: AuthContext = Depends(require_permission("tasks:write")),
    db: Session = Depends(get_db),
) -> TaskSubmissionResponse:
    tenant_id, application_id, environment = _resolve_scope(
        db,
        actor,
        permission="tasks:write",
        tenant_slug=payload.tenant_slug,
        application_key=payload.application_key,
        environment=payload.environment,
    )
    task = enqueue_task(
        db,
        TASK_TYPE_EVALUATION,
        payload.model_dump(),
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        requested_by=actor.user.email,
    )
    record_audit_event(
        db,
        actor=actor,
        event_type="ops.evaluation.submit",
        object_type="task_run",
        object_id=task.id,
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        payload={"task_type": TASK_TYPE_EVALUATION, "run_name": payload.run_name},
    )
    db.commit()
    return TaskSubmissionResponse(job_id=task.id, status=task.status)


@router.post("/audits/samples", response_model=TaskSubmissionResponse)
def submit_sample_audit(
    tenant_slug: str | None = None,
    application_key: str | None = None,
    actor: AuthContext = Depends(require_permission("tasks:write")),
    db: Session = Depends(get_db),
) -> TaskSubmissionResponse:
    tenant_id, application_id, _ = _resolve_scope(
        db,
        actor,
        permission="tasks:write",
        tenant_slug=tenant_slug,
        application_key=application_key,
    )
    task = enqueue_task(
        db,
        TASK_TYPE_SAMPLE_AUDIT,
        {},
        tenant_id=tenant_id,
        application_id=application_id,
        requested_by=actor.user.email,
    )
    record_audit_event(
        db,
        actor=actor,
        event_type="ops.sample_audit.submit",
        object_type="task_run",
        object_id=task.id,
        tenant_id=tenant_id,
        payload={"task_type": TASK_TYPE_SAMPLE_AUDIT},
    )
    db.commit()
    return TaskSubmissionResponse(job_id=task.id, status=task.status)


@router.post("/analysis/rules", response_model=TaskSubmissionResponse)
def submit_rule_effectiveness(
    run_id: int | None = None,
    actor: AuthContext = Depends(require_permission("tasks:write")),
    db: Session = Depends(get_db),
) -> TaskSubmissionResponse:
    tenant_id, application_id, environment = _resolve_scope(db, actor, permission="tasks:write", run_id=run_id)
    task = enqueue_task(
        db,
        TASK_TYPE_RULE_EFFECTIVENESS,
        {"run_id": run_id},
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        requested_by=actor.user.email,
    )
    record_audit_event(
        db,
        actor=actor,
        event_type="ops.rule_effectiveness.submit",
        object_type="task_run",
        object_id=task.id,
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        payload={"run_id": run_id},
    )
    db.commit()
    return TaskSubmissionResponse(job_id=task.id, status=task.status)


@router.post("/cases/build", response_model=TaskSubmissionResponse)
def submit_casebook(
    payload: CaseBuildRequest,
    actor: AuthContext = Depends(require_permission("cases:write")),
    db: Session = Depends(get_db),
) -> TaskSubmissionResponse:
    tenant_id, application_id, environment = _resolve_scope(
        db,
        actor,
        permission="cases:write",
        tenant_slug=payload.tenant_slug,
        run_id=payload.run_id,
    )
    task = enqueue_task(
        db,
        TASK_TYPE_CASEBOOK,
        payload.model_dump(),
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        requested_by=actor.user.email,
    )
    record_audit_event(
        db,
        actor=actor,
        event_type="ops.casebook.submit",
        object_type="task_run",
        object_id=task.id,
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        payload=payload.model_dump(),
    )
    db.commit()
    return TaskSubmissionResponse(job_id=task.id, status=task.status)


@router.post("/reports/weekly", response_model=TaskSubmissionResponse)
def submit_weekly_report(
    payload: WeeklyReportRequest,
    actor: AuthContext = Depends(require_permission("tasks:write")),
    db: Session = Depends(get_db),
) -> TaskSubmissionResponse:
    tenant_id, application_id, environment = _resolve_scope(
        db,
        actor,
        permission="tasks:write",
        tenant_slug=payload.tenant_slug,
        application_key=payload.application_key,
        environment=payload.environment,
    )
    task = enqueue_task(
        db,
        TASK_TYPE_WEEKLY_REPORT,
        payload.model_dump(),
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        requested_by=actor.user.email,
    )
    record_audit_event(
        db,
        actor=actor,
        event_type="ops.weekly_report.submit",
        object_type="task_run",
        object_id=task.id,
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        payload=payload.model_dump(),
    )
    db.commit()
    return TaskSubmissionResponse(job_id=task.id, status=task.status)


@router.post("/reports/postmortem", response_model=TaskSubmissionResponse)
def submit_postmortem(
    payload: PostmortemRequest,
    actor: AuthContext = Depends(require_permission("tasks:write")),
    db: Session = Depends(get_db),
) -> TaskSubmissionResponse:
    tenant_id, application_id, environment = _resolve_scope(
        db,
        actor,
        permission="tasks:write",
        tenant_slug=payload.tenant_slug,
        application_key=payload.application_key,
        environment=payload.environment,
        run_id=payload.run_id,
    )
    task = enqueue_task(
        db,
        TASK_TYPE_POSTMORTEM,
        payload.model_dump(),
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        requested_by=actor.user.email,
    )
    record_audit_event(
        db,
        actor=actor,
        event_type="ops.postmortem.submit",
        object_type="task_run",
        object_id=task.id,
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        payload=payload.model_dump(),
    )
    db.commit()
    return TaskSubmissionResponse(job_id=task.id, status=task.status)


@router.get("/tasks/{task_id}", response_model=TaskRunRead)
def get_task_status(
    task_id: int,
    actor: AuthContext = Depends(require_permission("tasks:read")),
    db: Session = Depends(get_db),
) -> TaskRun:
    task = get_task(db, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    ensure_actor_has_tenant_permission(actor, task.tenant_id, "tasks:read")
    return task


@router.get("/tasks", response_model=list[TaskRunRead])
def get_task_list(
    status: str | None = None,
    limit: int = Query(default=100, le=500),
    actor: AuthContext = Depends(require_permission("tasks:read")),
    db: Session = Depends(get_db),
) -> list[TaskRun]:
    tasks = list_tasks(db, status=status, limit=limit)
    if actor.is_superuser:
        return tasks
    visible = actor.visible_tenant_ids("tasks:read")
    return [task for task in tasks if task.tenant_id in visible]


@router.get("/review-queue", response_model=list[SampleReviewQueueItem])
def get_review_queue(
    needs_review: bool | None = None,
    boundary_sample_flag: bool | None = None,
    attack_type: str | None = None,
    scenario: str | None = None,
    limit: int = Query(default=100, le=500),
    actor: AuthContext = Depends(require_permission("review:read")),
    db: Session = Depends(get_db),
) -> list[SampleReviewQueueItem]:
    query = db.query(Sample)
    if not actor.is_superuser:
        query = query.filter(Sample.tenant_id.in_(sorted(actor.visible_tenant_ids("review:read"))))
    if needs_review is not None:
        query = query.filter(Sample.needs_review == needs_review)
    if boundary_sample_flag is not None:
        query = query.filter(Sample.boundary_sample_flag == boundary_sample_flag)
    if attack_type:
        query = query.filter(Sample.attack_category == attack_type)
    if scenario:
        query = query.filter(Sample.scenario == scenario)
    samples = query.order_by(Sample.created_at.desc()).limit(limit).all()
    return [
        SampleReviewQueueItem(
            id=sample.id,
            tenant_id=sample.tenant_id,
            application_id=sample.application_id,
            text=sample.text,
            sample_type=sample.sample_type,
            attack_category=sample.attack_category,
            expected_result=sample.expected_result,
            actual_result=sample.actual_result,
            scenario=sample.scenario,
            needs_review=sample.needs_review,
            boundary_sample_flag=sample.boundary_sample_flag,
            review_comment=sample.review_comment,
            audit_tips=sample_audit_tips(sample),
        )
        for sample in samples
    ]


@router.post("/review-tasks", response_model=ReviewTaskRead)
def create_review_task(
    payload: ReviewTaskCreate,
    actor: AuthContext = Depends(require_permission("review:write")),
    db: Session = Depends(get_db),
) -> ReviewTask:
    resolved_tenant_id: int | None = None
    resolved_application_id: int | None = None

    def merge_scope(candidate_tenant_id: int | None, candidate_application_id: int | None, source: str) -> None:
        nonlocal resolved_tenant_id, resolved_application_id
        if candidate_tenant_id is None:
            raise HTTPException(status_code=400, detail=f"{source} does not resolve to a tenant scope")
        if resolved_tenant_id is not None and resolved_tenant_id != candidate_tenant_id:
            raise HTTPException(status_code=400, detail=f"{source} conflicts with previously resolved tenant scope")
        if (
            resolved_application_id is not None
            and candidate_application_id is not None
            and resolved_application_id != candidate_application_id
        ):
            raise HTTPException(status_code=400, detail=f"{source} conflicts with previously resolved application scope")
        resolved_tenant_id = candidate_tenant_id
        if candidate_application_id is not None:
            resolved_application_id = candidate_application_id

    if payload.tenant_slug is not None or payload.application_key is not None:
        tenant_id, application_id, _ = _resolve_scope(
            db,
            actor,
            permission="review:write",
            tenant_slug=payload.tenant_slug,
            application_key=payload.application_key,
        )
        merge_scope(tenant_id, application_id, "explicit scope")
    if payload.sample_id is not None:
        sample = db.query(Sample).filter(Sample.id == payload.sample_id).one_or_none()
        if sample is None:
            raise HTTPException(status_code=404, detail="sample not found")
        ensure_actor_has_tenant_permission(actor, sample.tenant_id, "review:write")
        merge_scope(sample.tenant_id, sample.application_id, "sample_id")
    if payload.case_record_id is not None:
        case = db.query(CaseRecord).filter(CaseRecord.id == payload.case_record_id).one_or_none()
        if case is None:
            raise HTTPException(status_code=404, detail="case not found")
        ensure_actor_has_tenant_permission(actor, case.tenant_id, "review:write")
        merge_scope(case.tenant_id, case.application_id, "case_record_id")
    task = ReviewTask(
        sample_id=payload.sample_id,
        case_record_id=payload.case_record_id,
        tenant_id=resolved_tenant_id,
        application_id=resolved_application_id,
        assigned_to=payload.assigned_to,
        priority=payload.priority,
        structured_findings=payload.structured_findings,
    )
    db.add(task)
    db.flush()
    record_audit_event(
        db,
        actor=actor,
        event_type="ops.review_task.create",
        object_type="review_task",
        object_id=task.id,
        tenant_id=resolved_tenant_id,
        application_id=resolved_application_id,
        payload=payload.model_dump(),
    )
    db.commit()
    db.refresh(task)
    return task


@router.get("/review-tasks", response_model=list[ReviewTaskRead])
def list_review_tasks(
    status: str | None = None,
    assigned_to: str | None = None,
    actor: AuthContext = Depends(require_permission("review:read")),
    db: Session = Depends(get_db),
) -> list[ReviewTask]:
    query = db.query(ReviewTask)
    if status:
        query = query.filter(ReviewTask.status == status)
    if assigned_to:
        query = query.filter(ReviewTask.assigned_to == assigned_to)
    if not actor.is_superuser:
        query = query.filter(ReviewTask.tenant_id.in_(sorted(actor.visible_tenant_ids("review:read"))))
    return query.order_by(ReviewTask.id.desc()).all()


@router.get("/cases", response_model=list[CaseRead])
def get_cases(
    case_type: str | None = None,
    attack_type: str | None = None,
    root_cause: str | None = None,
    status: str | None = None,
    actor: AuthContext = Depends(require_permission("cases:read")),
    db: Session = Depends(get_db),
) -> list[CaseRead]:
    cases = list_cases(db, case_type=case_type, attack_category=attack_type, root_cause=root_cause, status=status)
    if actor.is_superuser:
        return cases
    visible = actor.visible_tenant_ids("cases:read")
    return [case for case in cases if case.tenant_id in visible]


@router.get("/evaluations/compare")
def compare_evaluations(
    run_ids: str,
    actor: AuthContext = Depends(require_permission("tasks:read")),
    db: Session = Depends(get_db),
) -> dict:
    try:
        parsed_ids = [int(item) for item in run_ids.split(",") if item.strip()]
        payload = StrategyCompareRequest(run_ids=parsed_ids)
    except (ValueError, ValidationError) as exc:
        raise HTTPException(status_code=400, detail="run_ids must be a comma-separated list of integers") from exc
    runs = db.query(EvaluationRun).filter(EvaluationRun.id.in_(payload.run_ids)).all()
    if len(runs) != len(payload.run_ids):
        raise HTTPException(status_code=404, detail="one or more evaluation runs not found")
    for run in runs:
        ensure_actor_has_tenant_permission(actor, run.tenant_id, "tasks:read")
    return compare_evaluation_runs(db, payload.run_ids)
