from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from core.config import get_settings
from core.database import get_db
from core.security import (
    AuthContext,
    ensure_actor_can_access_tenant,
    ensure_actor_has_tenant_permission,
    get_current_user,
    require_permission,
    require_superuser,
)
from models.entities import Application, EvaluationRun, Membership, PolicyBinding, Role, Sample, Tenant, User
from models.schemas import (
    ApplicationCreate,
    ApplicationRead,
    MembershipCreate,
    MembershipRead,
    PolicyBindingCreate,
    PolicyBindingRead,
    ReportRead,
    RoleRead,
    RuleEffectivenessRead,
    SampleCreate,
    SampleDetailRead,
    SampleImportResponse,
    SampleRead,
    SampleUpdate,
    TenantCreate,
    TenantRead,
    UserCreate,
    UserRead,
)
from services.audit_log import record_audit_event
from services.exceptions import SampleImportError
from services.rule_analysis import analyze_rule_effectiveness
from services.rule_engine import get_rule_engine
from services.sample_importer import import_samples, load_records_from_text


router = APIRouter(prefix="/admin", tags=["admin"])


def _visible_tenant_ids(actor: AuthContext) -> list[int] | None:
    return None if actor.is_superuser else sorted(actor.tenant_ids)


def _visible_tenant_ids_for_permission(actor: AuthContext, permission: str) -> list[int] | None:
    return None if actor.is_superuser else sorted(actor.visible_tenant_ids(permission))


def _load_tenant_for_actor(db: Session, actor: AuthContext, tenant_slug: str, permission: str | None = None) -> Tenant:
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).one_or_none()
    if tenant is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    ensure_actor_can_access_tenant(actor, tenant.id)
    if permission is not None:
        ensure_actor_has_tenant_permission(actor, tenant.id, permission)
    return tenant


def _resolve_sample_scope(
    db: Session,
    actor: AuthContext,
    *,
    tenant_slug: str | None,
    application_key: str | None,
    permission: str,
) -> tuple[int | None, int | None]:
    tenant_id: int | None = None
    application_id: int | None = None
    if tenant_slug is not None:
        tenant = _load_tenant_for_actor(db, actor, tenant_slug, permission)
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
    if not actor.is_superuser and tenant_id is None:
        visible = actor.visible_tenant_ids(permission)
        if len(visible) == 1:
            tenant_id = next(iter(visible))
        else:
            raise HTTPException(status_code=400, detail="tenant scope is required")
    return tenant_id, application_id


@router.post("/samples", response_model=SampleRead)
def create_sample(
    payload: SampleCreate,
    actor: AuthContext = Depends(require_permission("samples:write")),
    db: Session = Depends(get_db),
) -> Sample:
    tenant_id, application_id = _resolve_sample_scope(
        db,
        actor,
        tenant_slug=payload.tenant_slug,
        application_key=payload.application_key,
        permission="samples:write",
    )
    sample = Sample(
        tenant_id=tenant_id,
        application_id=application_id,
        **payload.model_dump(exclude={"tenant_slug", "application_key"}),
    )
    db.add(sample)
    db.flush()
    record_audit_event(
        db,
        actor=actor,
        event_type="admin.sample.create",
        object_type="sample",
        object_id=sample.id,
        tenant_id=tenant_id,
        application_id=application_id,
        payload={"sample_type": sample.sample_type, "attack_category": sample.attack_category},
    )
    db.commit()
    db.refresh(sample)
    return sample


@router.get("/samples", response_model=list[SampleRead])
def list_samples(
    sample_type: str | None = None,
    attack_category: str | None = None,
    risk_level: str | None = None,
    tag: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    tenant_slug: str | None = None,
    application_key: str | None = None,
    limit: int = Query(default=100, le=500),
    actor: AuthContext = Depends(require_permission("samples:read")),
    db: Session = Depends(get_db),
) -> list[Sample]:
    query = db.query(Sample)
    if tenant_slug is not None or application_key is not None:
        tenant_id, application_id = _resolve_sample_scope(
            db,
            actor,
            tenant_slug=tenant_slug,
            application_key=application_key,
            permission="samples:read",
        )
        if tenant_id is not None:
            query = query.filter(Sample.tenant_id == tenant_id)
        if application_id is not None:
            query = query.filter(Sample.application_id == application_id)
    elif not actor.is_superuser:
        visible = _visible_tenant_ids_for_permission(actor, "samples:read")
        query = query.filter(Sample.tenant_id.in_(visible))
    if sample_type:
        query = query.filter(Sample.sample_type == sample_type)
    if attack_category:
        query = query.filter(Sample.attack_category == attack_category)
    if risk_level:
        query = query.filter(Sample.risk_level == risk_level)
    if created_from:
        query = query.filter(Sample.created_at >= created_from)
    if created_to:
        query = query.filter(Sample.created_at <= created_to)
    samples = query.order_by(Sample.created_at.desc()).limit(limit).all()
    if tag:
        samples = [sample for sample in samples if tag in (sample.tags or [])]
    return samples


@router.get("/samples/{sample_id}", response_model=SampleDetailRead)
def get_sample(
    sample_id: int,
    actor: AuthContext = Depends(require_permission("samples:read")),
    db: Session = Depends(get_db),
) -> Sample:
    sample = db.query(Sample).filter(Sample.id == sample_id).one_or_none()
    if sample is None:
        raise HTTPException(status_code=404, detail="sample not found")
    ensure_actor_has_tenant_permission(actor, sample.tenant_id, "samples:read")
    return sample


@router.put("/samples/{sample_id}", response_model=SampleRead)
def update_sample(
    sample_id: int,
    payload: SampleUpdate,
    actor: AuthContext = Depends(require_permission("samples:write")),
    db: Session = Depends(get_db),
) -> Sample:
    sample = db.query(Sample).filter(Sample.id == sample_id).one_or_none()
    if sample is None:
        raise HTTPException(status_code=404, detail="sample not found")
    ensure_actor_has_tenant_permission(actor, sample.tenant_id, "samples:write")
    for key, value in payload.model_dump(exclude_unset=True, exclude={"tenant_slug", "application_key"}).items():
        setattr(sample, key, value)
    record_audit_event(
        db,
        actor=actor,
        event_type="admin.sample.update",
        object_type="sample",
        object_id=sample.id,
        tenant_id=sample.tenant_id,
        application_id=sample.application_id,
        payload=payload.model_dump(exclude_unset=True, exclude={"tenant_slug", "application_key"}),
    )
    db.add(sample)
    db.commit()
    db.refresh(sample)
    return sample


@router.delete("/samples/{sample_id}")
def delete_sample(
    sample_id: int,
    actor: AuthContext = Depends(require_permission("samples:write")),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    sample = db.query(Sample).filter(Sample.id == sample_id).one_or_none()
    if sample is None:
        raise HTTPException(status_code=404, detail="sample not found")
    ensure_actor_has_tenant_permission(actor, sample.tenant_id, "samples:write")
    record_audit_event(
        db,
        actor=actor,
        event_type="admin.sample.delete",
        object_type="sample",
        object_id=sample.id,
        tenant_id=sample.tenant_id,
        application_id=sample.application_id,
        payload={"sample_type": sample.sample_type},
    )
    db.delete(sample)
    db.commit()
    return {"status": "deleted"}


@router.post("/samples/import", response_model=SampleImportResponse)
async def import_sample_file(
    file: UploadFile = File(...),
    tenant_slug: str | None = None,
    application_key: str | None = None,
    actor: AuthContext = Depends(require_permission("samples:write")),
    db: Session = Depends(get_db),
) -> SampleImportResponse:
    settings = get_settings()
    suffix = Path(file.filename or "").suffix
    if suffix.lower() not in {".jsonl", ".csv"}:
        raise HTTPException(status_code=400, detail="unsupported file type")
    chunks: list[bytes] = []
    total_size = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail="uploaded file is too large")
        chunks.append(chunk)
    try:
        content = b"".join(chunks).decode("utf-8")
        records = load_records_from_text(content, suffix)
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="file must be utf-8 encoded") from exc
    except SampleImportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    tenant_id, application_id = _resolve_sample_scope(
        db,
        actor,
        tenant_slug=tenant_slug,
        application_key=application_key,
        permission="samples:write",
    )
    imported, skipped = import_samples(
        db,
        records,
        source=file.filename or "upload",
        tenant_id=tenant_id,
        application_id=application_id,
    )
    record_audit_event(
        db,
        actor=actor,
        event_type="admin.sample.import",
        object_type="sample_batch",
        object_id=file.filename or "upload",
        tenant_id=tenant_id,
        application_id=application_id,
        payload={"imported": imported, "skipped": skipped},
    )
    db.commit()
    return SampleImportResponse(imported=imported, skipped=skipped, source=file.filename or "upload")


@router.post("/rules/reload")
def reload_rules(
    actor: AuthContext = Depends(require_permission("rules:write")),
    db: Session = Depends(get_db),
) -> dict[str, int]:
    try:
        count = get_rule_engine().reload_rules(db=db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit_event(
        db,
        actor=actor,
        event_type="admin.rule.reload",
        object_type="rule_set",
        object_id="default",
        payload={"count": count},
    )
    db.commit()
    return {"reloaded_rules": count}


@router.get("/rules/effectiveness", response_model=list[RuleEffectivenessRead])
def get_rule_effectiveness(
    run_id: int | None = None,
    actor: AuthContext = Depends(require_permission("rules:read")),
    db: Session = Depends(get_db),
) -> list[RuleEffectivenessRead]:
    resolved_run_id = run_id
    if resolved_run_id is not None:
        run = db.query(EvaluationRun).filter(EvaluationRun.id == resolved_run_id).one_or_none()
        if run is None:
            raise HTTPException(status_code=404, detail="evaluation run not found")
        ensure_actor_has_tenant_permission(actor, run.tenant_id, "rules:read")
    elif not actor.is_superuser:
        visible = actor.visible_tenant_ids("rules:read")
        run = (
            db.query(EvaluationRun)
            .filter(EvaluationRun.tenant_id.in_(sorted(visible)))
            .order_by(EvaluationRun.id.desc())
            .first()
        )
        if run is None:
            return []
        resolved_run_id = run.id
    rows, _ = analyze_rule_effectiveness(db, run_id=resolved_run_id, write_report=False)
    return [RuleEffectivenessRead(**row) for row in rows]


@router.post("/tenants", response_model=TenantRead)
def create_tenant(
    payload: TenantCreate,
    actor: AuthContext = Depends(require_superuser),
    db: Session = Depends(get_db),
) -> Tenant:
    existing = db.query(Tenant).filter(Tenant.slug == payload.slug).one_or_none()
    if existing is not None:
        raise HTTPException(status_code=400, detail="tenant slug already exists")
    tenant = Tenant(**payload.model_dump())
    db.add(tenant)
    db.flush()
    record_audit_event(
        db,
        actor=actor,
        event_type="admin.tenant.create",
        object_type="tenant",
        object_id=tenant.id,
        tenant_id=tenant.id,
        payload=payload.model_dump(),
    )
    db.commit()
    db.refresh(tenant)
    return tenant


@router.get("/tenants", response_model=list[TenantRead])
def list_tenants(
    actor: AuthContext = Depends(require_permission("tenants:read")),
    db: Session = Depends(get_db),
) -> list[Tenant]:
    query = db.query(Tenant)
    visible = _visible_tenant_ids_for_permission(actor, "tenants:read")
    if visible is not None:
        query = query.filter(Tenant.id.in_(visible))
    return query.order_by(Tenant.id.asc()).all()


@router.post("/users", response_model=UserRead)
def create_user(
    payload: UserCreate,
    actor: AuthContext = Depends(require_superuser),
    db: Session = Depends(get_db),
) -> User:
    from core.security import hash_password

    existing = db.query(User).filter(User.email == payload.email.lower()).one_or_none()
    if existing is not None:
        raise HTTPException(status_code=400, detail="user email already exists")
    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        is_active=True,
        is_superuser=payload.is_superuser,
    )
    db.add(user)
    db.flush()
    record_audit_event(
        db,
        actor=actor,
        event_type="admin.user.create",
        object_type="user",
        object_id=user.id,
        payload={"email": user.email, "is_superuser": user.is_superuser},
    )
    db.commit()
    db.refresh(user)
    return user


@router.get("/users", response_model=list[UserRead])
def list_users(
    _: AuthContext = Depends(require_superuser),
    db: Session = Depends(get_db),
) -> list[User]:
    return db.query(User).order_by(User.id.asc()).all()


@router.get("/roles", response_model=list[RoleRead])
def list_roles(
    _: AuthContext = Depends(require_permission("users:write")),
    db: Session = Depends(get_db),
) -> list[Role]:
    return db.query(Role).order_by(Role.name.asc()).all()


@router.post("/memberships", response_model=MembershipRead)
def create_membership(
    payload: MembershipCreate,
    actor: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Membership:
    tenant = db.query(Tenant).filter(Tenant.slug == payload.tenant_slug).one_or_none()
    if tenant is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    role = db.query(Role).filter(Role.name == payload.role_name).one_or_none()
    if role is None:
        raise HTTPException(status_code=404, detail="role not found")
    if not actor.is_superuser:
        ensure_actor_has_tenant_permission(actor, tenant.id, "users:write")
        if payload.role_name == "tenant_admin":
            raise HTTPException(status_code=403, detail="only superuser can assign tenant_admin")
    existing = (
        db.query(Membership)
        .filter(Membership.user_id == payload.user_id, Membership.tenant_id == tenant.id, Membership.role_id == role.id)
        .one_or_none()
    )
    if existing is not None:
        return existing
    membership = Membership(user_id=payload.user_id, tenant_id=tenant.id, role_id=role.id)
    db.add(membership)
    db.flush()
    record_audit_event(
        db,
        actor=actor,
        event_type="admin.membership.create",
        object_type="membership",
        object_id=membership.id,
        tenant_id=tenant.id,
        payload={"user_id": payload.user_id, "role_name": payload.role_name},
    )
    db.commit()
    db.refresh(membership)
    return membership


@router.get("/memberships", response_model=list[MembershipRead])
def list_memberships(
    tenant_slug: str | None = None,
    actor: AuthContext = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Membership]:
    if not actor.is_superuser and not actor.has_permission("users:write"):
        raise HTTPException(status_code=403, detail="missing permission: users:write")
    query = db.query(Membership)
    if tenant_slug:
        tenant = _load_tenant_for_actor(db, actor, tenant_slug, "users:write")
        query = query.filter(Membership.tenant_id == tenant.id)
    elif not actor.is_superuser:
        query = query.filter(Membership.tenant_id.in_(sorted(actor.visible_tenant_ids("users:write"))))
    return query.order_by(Membership.id.asc()).all()


@router.post("/applications", response_model=ApplicationRead)
def create_application(
    payload: ApplicationCreate,
    actor: AuthContext = Depends(require_permission("applications:write")),
    db: Session = Depends(get_db),
) -> Application:
    tenant = _load_tenant_for_actor(db, actor, payload.tenant_slug, "applications:write")
    existing = db.query(Application).filter(Application.app_key == payload.app_key).one_or_none()
    if existing is not None:
        raise HTTPException(status_code=400, detail="application key already exists")
    application = Application(
        tenant_id=tenant.id,
        name=payload.name,
        app_key=payload.app_key,
        environment=payload.environment,
        description=payload.description,
    )
    db.add(application)
    db.flush()
    record_audit_event(
        db,
        actor=actor,
        event_type="admin.application.create",
        object_type="application",
        object_id=application.id,
        tenant_id=tenant.id,
        application_id=application.id,
        environment=application.environment,
        payload=payload.model_dump(),
    )
    db.commit()
    db.refresh(application)
    return application


@router.get("/applications", response_model=list[ApplicationRead])
def list_applications(
    tenant_slug: str | None = None,
    actor: AuthContext = Depends(require_permission("applications:read")),
    db: Session = Depends(get_db),
) -> list[Application]:
    query = db.query(Application)
    if tenant_slug:
        tenant = _load_tenant_for_actor(db, actor, tenant_slug, "applications:read")
        query = query.filter(Application.tenant_id == tenant.id)
    elif not actor.is_superuser:
        query = query.filter(Application.tenant_id.in_(sorted(actor.visible_tenant_ids("applications:read"))))
    return query.order_by(Application.id.asc()).all()


@router.post("/policy-bindings", response_model=PolicyBindingRead)
def create_policy_binding(
    payload: PolicyBindingCreate,
    actor: AuthContext = Depends(require_permission("policies:write")),
    db: Session = Depends(get_db),
) -> PolicyBinding:
    tenant = _load_tenant_for_actor(db, actor, payload.tenant_slug, "policies:write")
    application = None
    if payload.application_key:
        application = db.query(Application).filter(Application.app_key == payload.application_key).one_or_none()
        if application is None:
            raise HTTPException(status_code=404, detail="application not found")
        if application.tenant_id != tenant.id:
            raise HTTPException(status_code=400, detail="application does not belong to tenant")
    binding = PolicyBinding(
        tenant_id=tenant.id,
        application_id=application.id if application else None,
        environment=payload.environment,
        scenario=payload.scenario,
        strategy_name=payload.strategy_name,
        rule_allowlist=payload.rule_allowlist,
        rule_blocklist=payload.rule_blocklist,
    )
    db.add(binding)
    db.flush()
    record_audit_event(
        db,
        actor=actor,
        event_type="admin.policy_binding.create",
        object_type="policy_binding",
        object_id=binding.id,
        tenant_id=tenant.id,
        application_id=binding.application_id,
        environment=binding.environment,
        payload=payload.model_dump(),
    )
    db.commit()
    db.refresh(binding)
    return binding


@router.get("/policy-bindings", response_model=list[PolicyBindingRead])
def list_policy_bindings(
    tenant_slug: str | None = None,
    actor: AuthContext = Depends(require_permission("policies:read")),
    db: Session = Depends(get_db),
) -> list[PolicyBinding]:
    query = db.query(PolicyBinding)
    if tenant_slug:
        tenant = _load_tenant_for_actor(db, actor, tenant_slug, "policies:read")
        query = query.filter(PolicyBinding.tenant_id == tenant.id)
    elif not actor.is_superuser:
        query = query.filter(PolicyBinding.tenant_id.in_(sorted(actor.visible_tenant_ids("policies:read"))))
    return query.order_by(PolicyBinding.id.asc()).all()


@router.get("/reports/{run_id}", response_model=ReportRead)
def get_report(
    run_id: int,
    actor: AuthContext = Depends(require_permission("reports:read")),
    db: Session = Depends(get_db),
) -> ReportRead:
    settings = get_settings()
    run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).one_or_none()
    if run is None or not run.report_path:
        raise HTTPException(status_code=404, detail="report not found")
    ensure_actor_has_tenant_permission(actor, run.tenant_id, "reports:read")
    report_path = Path(run.report_path).resolve()
    try:
        report_path.relative_to(settings.report_dir.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid report path") from exc
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="report file not found")
    return ReportRead(run_id=run.id, report_path=run.report_path, content=report_path.read_text(encoding="utf-8"))
