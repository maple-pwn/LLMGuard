from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from core.config import get_settings


def _validate_dynamic_text_limit(value: str | None, limit: int, field_name: str) -> str | None:
    if value is None:
        return None
    if len(value) > limit:
        raise ValueError(f"{field_name} exceeds max length {limit}")
    return value


class ScanRequest(BaseModel):
    user_input: str = Field(min_length=1)
    retrieved_context: str | None = None
    model_output: str | None = None
    scenario: str | None = Field(default="general_assistant", max_length=64)
    session_id: str | None = Field(default=None, max_length=128)
    strategy_name: str | None = Field(default="full_stack", max_length=64)
    tenant_slug: str | None = Field(default="default", max_length=64)
    application_key: str | None = Field(default=None, max_length=96)
    environment: str | None = Field(default="prod", max_length=32)
    request_metadata: dict[str, Any] | None = None

    @field_validator("user_input", "retrieved_context", "model_output")
    @classmethod
    def validate_scan_lengths(cls, value: str | None, info: ValidationInfo) -> str | None:
        settings = get_settings()
        limits = {
            "user_input": settings.max_user_input_chars,
            "retrieved_context": settings.max_context_chars,
            "model_output": settings.max_model_output_chars,
        }
        return _validate_dynamic_text_limit(value, limits[info.field_name], info.field_name)


class TriggeredRule(BaseModel):
    rule_id: str
    name: str
    category: str
    severity: str
    weight: float
    target: str
    matched_text: str
    explanation: str


class ScanResponse(BaseModel):
    risk_type: str
    risk_score: float
    triggered_rules: list[TriggeredRule]
    decision: str
    reason: str
    latency_ms: float
    classifier_score: float | None = None
    output_filter_score: float | None = None


class SampleBase(BaseModel):
    tenant_slug: str | None = Field(default=None, max_length=64)
    application_key: str | None = Field(default=None, max_length=96)
    text: str = Field(min_length=1)
    sample_type: str = Field(max_length=32)
    attack_category: str | None = Field(default=None, max_length=64)
    attack_subtype: str | None = Field(default=None, max_length=64)
    risk_level: str | None = Field(default=None, max_length=32)
    source: str | None = Field(default=None, max_length=128)
    tags: list[str] = Field(default_factory=list, max_length=32)
    expected_result: str = Field(max_length=16)
    actual_result: str | None = Field(default=None, max_length=16)
    reviewer: str | None = Field(default=None, max_length=64)
    review_status: str = Field(default="pending", max_length=32)
    label_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    duplicate_group_id: str | None = Field(default=None, max_length=64)
    boundary_sample_flag: bool = False
    needs_review: bool = False
    review_comment: str | None = Field(default=None, max_length=1000)
    scenario: str | None = Field(default=None, max_length=64)
    retrieved_context: str | None = None
    model_output: str | None = None

    @field_validator("text", "retrieved_context", "model_output")
    @classmethod
    def validate_sample_lengths(cls, value: str | None, info: ValidationInfo) -> str | None:
        settings = get_settings()
        limits = {
            "text": settings.max_user_input_chars,
            "retrieved_context": settings.max_context_chars,
            "model_output": settings.max_model_output_chars,
        }
        return _validate_dynamic_text_limit(value, limits[info.field_name], info.field_name)


class SampleCreate(SampleBase):
    pass


class SampleUpdate(BaseModel):
    text: str | None = Field(default=None, min_length=1)
    sample_type: str | None = Field(default=None, max_length=32)
    attack_category: str | None = Field(default=None, max_length=64)
    attack_subtype: str | None = Field(default=None, max_length=64)
    risk_level: str | None = Field(default=None, max_length=32)
    source: str | None = Field(default=None, max_length=128)
    tags: list[str] | None = Field(default=None, max_length=32)
    expected_result: str | None = Field(default=None, max_length=16)
    actual_result: str | None = Field(default=None, max_length=16)
    reviewer: str | None = Field(default=None, max_length=64)
    review_status: str | None = Field(default=None, max_length=32)
    label_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    duplicate_group_id: str | None = Field(default=None, max_length=64)
    boundary_sample_flag: bool | None = None
    needs_review: bool | None = None
    review_comment: str | None = Field(default=None, max_length=1000)
    scenario: str | None = Field(default=None, max_length=64)
    retrieved_context: str | None = None
    model_output: str | None = None

    @field_validator("text", "retrieved_context", "model_output")
    @classmethod
    def validate_update_lengths(cls, value: str | None, info: ValidationInfo) -> str | None:
        settings = get_settings()
        limits = {
            "text": settings.max_user_input_chars,
            "retrieved_context": settings.max_context_chars,
            "model_output": settings.max_model_output_chars,
        }
        return _validate_dynamic_text_limit(value, limits[info.field_name], info.field_name)


class SampleRead(BaseModel):
    id: int
    tenant_id: int | None = None
    application_id: int | None = None
    text: str
    sample_type: str
    attack_category: str | None = None
    attack_subtype: str | None = None
    risk_level: str | None = None
    source: str | None = None
    tags: list[str] = Field(default_factory=list)
    expected_result: str
    actual_result: str | None = None
    reviewer: str | None = None
    review_status: str
    label_confidence: float | None = None
    duplicate_group_id: str | None = None
    boundary_sample_flag: bool = False
    needs_review: bool = False
    review_comment: str | None = None
    scenario: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SampleDetailRead(SampleRead):
    retrieved_context: str | None = None
    model_output: str | None = None


class SampleImportResponse(BaseModel):
    imported: int
    skipped: int
    source: str


class EvaluationRequest(BaseModel):
    run_name: str = Field(default="default_evaluation", max_length=128)
    strategy_names: list[str] = Field(
        default_factory=lambda: ["rules_only", "rules_classifier", "full_stack"],
        min_length=1,
    )
    sample_ids: list[int] | None = None
    enable_threshold_scan: bool = True
    tenant_slug: str | None = Field(default=None, max_length=64)
    application_key: str | None = Field(default=None, max_length=96)
    environment: str | None = Field(default=None, max_length=32)

    @field_validator("strategy_names")
    @classmethod
    def validate_strategy_names(cls, value: list[str]) -> list[str]:
        settings = get_settings()
        if not value:
            raise ValueError("strategy_names must not be empty")
        if len(set(value)) != len(value):
            raise ValueError("strategy_names contains duplicates")
        if len(value) > settings.max_strategy_count:
            raise ValueError(f"strategy_names exceeds max count {settings.max_strategy_count}")
        return value

    @field_validator("sample_ids")
    @classmethod
    def validate_sample_ids(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return value
        settings = get_settings()
        if len(value) > settings.max_eval_samples:
            raise ValueError(f"sample_ids exceeds max count {settings.max_eval_samples}")
        return value


class EvaluationResponse(BaseModel):
    run_id: int
    strategies: list[str]
    metrics: dict[str, Any]
    report_path: str | None = None


class ReportRead(BaseModel):
    run_id: int
    report_path: str | None
    content: str


class SampleReviewQueueItem(BaseModel):
    id: int
    tenant_id: int | None = None
    application_id: int | None = None
    text: str
    sample_type: str
    attack_category: str | None = None
    expected_result: str
    actual_result: str | None = None
    scenario: str | None = None
    needs_review: bool
    boundary_sample_flag: bool
    review_comment: str | None = None
    audit_tips: list[str] = Field(default_factory=list)


class CaseRead(BaseModel):
    id: int
    sample_id: int | None = None
    evaluation_run_id: int | None = None
    tenant_id: int | None = None
    application_id: int | None = None
    case_type: str
    attack_category: str | None = None
    root_cause: str
    triggered_rules: list[dict] = Field(default_factory=list)
    risk_score: float | None = None
    expected_decision: str
    actual_decision: str
    analysis_text: str
    fix_suggestion: str
    owner: str | None = None
    status: str
    doc_path: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseBuildRequest(BaseModel):
    run_id: int | None = None
    tenant_slug: str | None = Field(default=None, max_length=64)
    owner: str | None = Field(default="security_ops", max_length=64)


class StrategyCompareRequest(BaseModel):
    run_ids: list[int] = Field(min_length=1, max_length=10)


class GeneratedReportResponse(BaseModel):
    path: str
    title: str


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    slug: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=500)


class TenantRead(BaseModel):
    id: int
    name: str
    slug: str
    description: str | None = None
    enabled: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApplicationCreate(BaseModel):
    tenant_slug: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    app_key: str = Field(min_length=1, max_length=96)
    environment: str = Field(default="prod", max_length=32)
    description: str | None = Field(default=None, max_length=500)


class ApplicationRead(BaseModel):
    id: int
    tenant_id: int
    name: str
    app_key: str
    environment: str
    description: str | None = None
    enabled: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PolicyBindingCreate(BaseModel):
    tenant_slug: str = Field(min_length=1, max_length=64)
    application_key: str | None = Field(default=None, max_length=96)
    environment: str = Field(default="prod", max_length=32)
    scenario: str | None = Field(default=None, max_length=64)
    strategy_name: str = Field(min_length=1, max_length=64)
    rule_allowlist: list[str] = Field(default_factory=list, max_length=128)
    rule_blocklist: list[str] = Field(default_factory=list, max_length=128)


class PolicyBindingRead(BaseModel):
    id: int
    tenant_id: int
    application_id: int | None = None
    environment: str
    scenario: str | None = None
    strategy_name: str
    rule_allowlist: list[str] = Field(default_factory=list)
    rule_blocklist: list[str] = Field(default_factory=list)
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TaskSubmissionResponse(BaseModel):
    job_id: int
    status: str


class TaskRunRead(BaseModel):
    id: int
    task_type: str
    status: str
    queue_backend: str
    backend_job_id: str | None = None
    idempotency_key: str | None = None
    tenant_id: int | None = None
    application_id: int | None = None
    environment: str | None = None
    payload: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    error_message: str | None = None
    artifact_uri: str | None = None
    attempts: int
    max_retries: int
    timeout_seconds: int
    execution_log: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime
    started_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    finished_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class ReviewTaskRead(BaseModel):
    id: int
    sample_id: int | None = None
    case_record_id: int | None = None
    tenant_id: int | None = None
    application_id: int | None = None
    status: str
    assigned_to: str | None = None
    priority: str
    structured_findings: dict[str, Any] | None = None
    resolution: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReviewTaskCreate(BaseModel):
    sample_id: int | None = None
    case_record_id: int | None = None
    tenant_slug: str | None = Field(default=None, max_length=64)
    application_key: str | None = Field(default=None, max_length=96)
    assigned_to: str | None = Field(default=None, max_length=64)
    priority: str = Field(default="medium", max_length=16)
    structured_findings: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_scope_presence(self) -> "ReviewTaskCreate":
        if not any(
            [
                self.sample_id is not None,
                self.case_record_id is not None,
                self.tenant_slug is not None,
                self.application_key is not None,
            ]
        ):
            raise ValueError("review task must be scoped by sample_id, case_record_id, tenant_slug, or application_key")
        return self


class RuleEffectivenessRead(BaseModel):
    rule_id: str
    name: str
    rule_version: str
    category: str
    hit_count: int
    hit_sample_type_distribution: dict[str, int]
    hit_attack_distribution: dict[str, int]
    block_contribution: int
    review_contribution: int
    false_positive_count: int
    missed_opportunity_count: int


class WeeklyReportRequest(BaseModel):
    title: str = Field(default="weekly_report", max_length=128)
    tenant_slug: str | None = Field(default=None, max_length=64)
    application_key: str | None = Field(default=None, max_length=96)
    environment: str | None = Field(default=None, max_length=32)


class PostmortemRequest(BaseModel):
    title: str = Field(default="evaluation_postmortem", max_length=128)
    run_id: int | None = None
    tenant_slug: str | None = Field(default=None, max_length=64)
    application_key: str | None = Field(default=None, max_length=96)
    environment: str | None = Field(default=None, max_length=32)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    full_name: str | None = Field(default=None, max_length=128)
    password: str = Field(min_length=8, max_length=128)
    is_superuser: bool = False


class UserRead(BaseModel):
    id: int
    email: str
    full_name: str | None = None
    is_active: bool
    is_superuser: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RoleRead(BaseModel):
    id: int
    name: str
    description: str | None = None

    model_config = ConfigDict(from_attributes=True)


class MembershipCreate(BaseModel):
    user_id: int
    tenant_slug: str = Field(min_length=1, max_length=64)
    role_name: str = Field(min_length=1, max_length=64)


class MembershipRead(BaseModel):
    id: int
    user_id: int
    tenant_id: int
    role_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CurrentUserMembershipRead(BaseModel):
    tenant_id: int
    role_id: int


class CurrentUserRead(BaseModel):
    id: int
    email: str
    full_name: str | None = None
    is_superuser: bool
    permissions: list[str] = Field(default_factory=list)
    tenant_ids: list[int] = Field(default_factory=list)
    memberships: list[CurrentUserMembershipRead] = Field(default_factory=list)
