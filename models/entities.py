from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    full_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(96), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role_id", "permission_id", name="uq_role_permissions_role_permission"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), nullable=False, index=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    app_key: Mapped[str] = mapped_column(String(96), unique=True, nullable=False, index=True)
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="prod", index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class PolicyBinding(Base):
    __tablename__ = "policy_bindings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("applications.id"), nullable=True, index=True)
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="prod", index=True)
    scenario: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    strategy_name: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_allowlist: Mapped[list[str] | None] = mapped_column(JSON, default=list)
    rule_blocklist: Mapped[list[str] | None] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id", "role_id", name="uq_memberships_user_tenant_role"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False, index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Sample(Base):
    __tablename__ = "samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("applications.id"), nullable=True, index=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    sample_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    attack_category: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    attack_subtype: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(JSON, default=list)
    expected_result: Mapped[str] = mapped_column(String(16), nullable=False)
    actual_result: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reviewer: Mapped[str | None] = mapped_column(String(64), nullable=True)
    review_status: Mapped[str] = mapped_column(String(32), default="pending")
    label_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    duplicate_group_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    boundary_sample_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    review_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    scenario: Mapped[str | None] = mapped_column(String(64), nullable=True)
    retrieved_context: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    strategy_name: Mapped[str] = mapped_column(String(128), nullable=False, default="comparison")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="created")
    dataset_source: Mapped[str | None] = mapped_column(String(256), nullable=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("applications.id"), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    requested_strategies: Mapped[list[str] | None] = mapped_column(JSON, default=list)
    metrics: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    threshold_scan: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    report_path: Mapped[str | None] = mapped_column(String(256), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class DetectionResult(Base):
    __tablename__ = "detection_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[int | None] = mapped_column(ForeignKey("samples.id"), nullable=True)
    evaluation_run_id: Mapped[int | None] = mapped_column(ForeignKey("evaluation_runs.id"), nullable=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("applications.id"), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    strategy_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scenario: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_input: Mapped[str] = mapped_column(Text, nullable=False)
    retrieved_context: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_type: Mapped[str] = mapped_column(String(128), nullable=False, default="benign")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    triggered_rules: Mapped[list[dict] | None] = mapped_column(JSON, default=list)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    classifier_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    output_filter_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    attribution_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    weight: Mapped[float] = mapped_column(Float, default=0.5)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    targets: Mapped[list[str] | None] = mapped_column(JSON, default=list)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_file: Mapped[str | None] = mapped_column(String(256), nullable=True)
    change_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class StrategyConfig(Base):
    __tablename__ = "strategy_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enable_rules: Mapped[bool] = mapped_column(Boolean, default=True)
    enable_classifier: Mapped[bool] = mapped_column(Boolean, default=True)
    enable_output_filter: Mapped[bool] = mapped_column(Boolean, default=False)
    strategy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    rule_selection: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    review_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.55)
    block_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.80)
    output_filter_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.80)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class CaseRecord(Base):
    __tablename__ = "case_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[int | None] = mapped_column(ForeignKey("samples.id"), nullable=True)
    evaluation_run_id: Mapped[int | None] = mapped_column(ForeignKey("evaluation_runs.id"), nullable=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("applications.id"), nullable=True, index=True)
    case_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    attack_category: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    root_cause: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    triggered_rules: Mapped[list[dict] | None] = mapped_column(JSON, default=list)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    expected_decision: Mapped[str] = mapped_column(String(16), nullable=False)
    actual_decision: Mapped[str] = mapped_column(String(16), nullable=False)
    analysis_text: Mapped[str] = mapped_column(Text, nullable=False)
    fix_suggestion: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)
    doc_path: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ReviewTask(Base):
    __tablename__ = "review_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[int | None] = mapped_column(ForeignKey("samples.id"), nullable=True, index=True)
    case_record_id: Mapped[int | None] = mapped_column(ForeignKey("case_records.id"), nullable=True, index=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("applications.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    assigned_to: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    structured_findings: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    resolution: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class TaskRun(Base):
    __tablename__ = "task_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    queue_backend: Mapped[str] = mapped_column(String(32), nullable=False, default="database")
    backend_job_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    active_dedup_key: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("applications.id"), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    artifact_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    execution_log: Mapped[list[dict] | None] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("applications.id"), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    object_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    object_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    risk_type: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    request_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    request_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    immutable_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("applications.id"), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
