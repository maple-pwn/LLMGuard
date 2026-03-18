"""initial platform schema

Revision ID: 20260416_01
Revises: None
Create Date: 2026-04-16 18:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260416_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=128), nullable=True),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "roles",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_roles_name", "roles", ["name"])

    op.create_table(
        "permissions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=96), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_permissions_name", "permissions", ["name"])

    op.create_table(
        "role_permissions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("role_id", sa.Integer(), sa.ForeignKey("roles.id"), nullable=False),
        sa.Column("permission_id", sa.Integer(), sa.ForeignKey("permissions.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("role_id", "permission_id", name="uq_role_permissions_role_permission"),
    )
    op.create_index("ix_role_permissions_permission_id", "role_permissions", ["permission_id"])
    op.create_index("ix_role_permissions_role_id", "role_permissions", ["role_id"])

    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"])

    op.create_table(
        "applications",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("app_key", sa.String(length=96), nullable=False),
        sa.Column("environment", sa.String(length=32), nullable=False, server_default="prod"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("app_key"),
    )
    op.create_index("ix_applications_app_key", "applications", ["app_key"])
    op.create_index("ix_applications_environment", "applications", ["environment"])
    op.create_index("ix_applications_tenant_id", "applications", ["tenant_id"])

    op.create_table(
        "policy_bindings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("application_id", sa.Integer(), sa.ForeignKey("applications.id"), nullable=True),
        sa.Column("environment", sa.String(length=32), nullable=False, server_default="prod"),
        sa.Column("scenario", sa.String(length=64), nullable=True),
        sa.Column("strategy_name", sa.String(length=64), nullable=False),
        sa.Column("rule_allowlist", sa.JSON(), nullable=True),
        sa.Column("rule_blocklist", sa.JSON(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_policy_bindings_application_id", "policy_bindings", ["application_id"])
    op.create_index("ix_policy_bindings_environment", "policy_bindings", ["environment"])
    op.create_index("ix_policy_bindings_scenario", "policy_bindings", ["scenario"])
    op.create_index("ix_policy_bindings_tenant_id", "policy_bindings", ["tenant_id"])

    op.create_table(
        "memberships",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("role_id", sa.Integer(), sa.ForeignKey("roles.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "tenant_id", "role_id", name="uq_memberships_user_tenant_role"),
    )
    op.create_index("ix_memberships_role_id", "memberships", ["role_id"])
    op.create_index("ix_memberships_tenant_id", "memberships", ["tenant_id"])
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])

    op.create_table(
        "samples",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("application_id", sa.Integer(), sa.ForeignKey("applications.id"), nullable=True),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("sample_type", sa.String(length=32), nullable=False),
        sa.Column("attack_category", sa.String(length=64), nullable=True),
        sa.Column("attack_subtype", sa.String(length=64), nullable=True),
        sa.Column("risk_level", sa.String(length=32), nullable=True),
        sa.Column("source", sa.String(length=128), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("expected_result", sa.String(length=16), nullable=False),
        sa.Column("actual_result", sa.String(length=16), nullable=True),
        sa.Column("reviewer", sa.String(length=64), nullable=True),
        sa.Column("review_status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("label_confidence", sa.Float(), nullable=True),
        sa.Column("duplicate_group_id", sa.String(length=64), nullable=True),
        sa.Column("boundary_sample_flag", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("needs_review", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("review_comment", sa.Text(), nullable=True),
        sa.Column("scenario", sa.String(length=64), nullable=True),
        sa.Column("retrieved_context", sa.Text(), nullable=True),
        sa.Column("model_output", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_samples_application_id", "samples", ["application_id"])
    op.create_index("ix_samples_attack_category", "samples", ["attack_category"])
    op.create_index("ix_samples_duplicate_group_id", "samples", ["duplicate_group_id"])
    op.create_index("ix_samples_needs_review", "samples", ["needs_review"])
    op.create_index("ix_samples_risk_level", "samples", ["risk_level"])
    op.create_index("ix_samples_sample_type", "samples", ["sample_type"])
    op.create_index("ix_samples_tenant_id", "samples", ["tenant_id"])

    op.create_table(
        "evaluation_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("strategy_name", sa.String(length=128), nullable=False, server_default="comparison"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="created"),
        sa.Column("dataset_source", sa.String(length=256), nullable=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("application_id", sa.Integer(), sa.ForeignKey("applications.id"), nullable=True),
        sa.Column("environment", sa.String(length=32), nullable=True),
        sa.Column("requested_strategies", sa.JSON(), nullable=True),
        sa.Column("metrics", sa.JSON(), nullable=True),
        sa.Column("threshold_scan", sa.JSON(), nullable=True),
        sa.Column("report_path", sa.String(length=256), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_evaluation_runs_application_id", "evaluation_runs", ["application_id"])
    op.create_index("ix_evaluation_runs_environment", "evaluation_runs", ["environment"])
    op.create_index("ix_evaluation_runs_tenant_id", "evaluation_runs", ["tenant_id"])

    op.create_table(
        "rules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("weight", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False, server_default="v1"),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        sa.Column("targets", sa.JSON(), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("source_file", sa.String(length=256), nullable=True),
        sa.Column("change_note", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("rule_id"),
    )

    op.create_table(
        "strategy_configs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enable_rules", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("enable_classifier", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("enable_output_filter", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("strategy_version", sa.String(length=32), nullable=False, server_default="v1"),
        sa.Column("rule_selection", sa.JSON(), nullable=True),
        sa.Column("review_threshold", sa.Float(), nullable=False, server_default="0.55"),
        sa.Column("block_threshold", sa.Float(), nullable=False, server_default="0.80"),
        sa.Column("output_filter_threshold", sa.Float(), nullable=False, server_default="0.80"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "detection_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("sample_id", sa.Integer(), sa.ForeignKey("samples.id"), nullable=True),
        sa.Column("evaluation_run_id", sa.Integer(), sa.ForeignKey("evaluation_runs.id"), nullable=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("application_id", sa.Integer(), sa.ForeignKey("applications.id"), nullable=True),
        sa.Column("environment", sa.String(length=32), nullable=True),
        sa.Column("strategy_name", sa.String(length=64), nullable=True),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("scenario", sa.String(length=64), nullable=True),
        sa.Column("user_input", sa.Text(), nullable=False),
        sa.Column("retrieved_context", sa.Text(), nullable=True),
        sa.Column("model_output", sa.Text(), nullable=True),
        sa.Column("risk_type", sa.String(length=128), nullable=False, server_default="benign"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("triggered_rules", sa.JSON(), nullable=True),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False),
        sa.Column("classifier_score", sa.Float(), nullable=True),
        sa.Column("output_filter_score", sa.Float(), nullable=True),
        sa.Column("attribution_label", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_detection_results_application_id", "detection_results", ["application_id"])
    op.create_index("ix_detection_results_environment", "detection_results", ["environment"])
    op.create_index("ix_detection_results_tenant_id", "detection_results", ["tenant_id"])

    op.create_table(
        "case_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("sample_id", sa.Integer(), sa.ForeignKey("samples.id"), nullable=True),
        sa.Column("evaluation_run_id", sa.Integer(), sa.ForeignKey("evaluation_runs.id"), nullable=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("application_id", sa.Integer(), sa.ForeignKey("applications.id"), nullable=True),
        sa.Column("case_type", sa.String(length=32), nullable=False),
        sa.Column("attack_category", sa.String(length=64), nullable=True),
        sa.Column("root_cause", sa.String(length=64), nullable=False),
        sa.Column("triggered_rules", sa.JSON(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("expected_decision", sa.String(length=16), nullable=False),
        sa.Column("actual_decision", sa.String(length=16), nullable=False),
        sa.Column("analysis_text", sa.Text(), nullable=False),
        sa.Column("fix_suggestion", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("doc_path", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_case_records_application_id", "case_records", ["application_id"])
    op.create_index("ix_case_records_attack_category", "case_records", ["attack_category"])
    op.create_index("ix_case_records_case_type", "case_records", ["case_type"])
    op.create_index("ix_case_records_root_cause", "case_records", ["root_cause"])
    op.create_index("ix_case_records_status", "case_records", ["status"])
    op.create_index("ix_case_records_tenant_id", "case_records", ["tenant_id"])

    op.create_table(
        "review_tasks",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("sample_id", sa.Integer(), sa.ForeignKey("samples.id"), nullable=True),
        sa.Column("case_record_id", sa.Integer(), sa.ForeignKey("case_records.id"), nullable=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("application_id", sa.Integer(), sa.ForeignKey("applications.id"), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("assigned_to", sa.String(length=64), nullable=True),
        sa.Column("priority", sa.String(length=16), nullable=False, server_default="medium"),
        sa.Column("structured_findings", sa.JSON(), nullable=True),
        sa.Column("resolution", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_review_tasks_application_id", "review_tasks", ["application_id"])
    op.create_index("ix_review_tasks_assigned_to", "review_tasks", ["assigned_to"])
    op.create_index("ix_review_tasks_case_record_id", "review_tasks", ["case_record_id"])
    op.create_index("ix_review_tasks_sample_id", "review_tasks", ["sample_id"])
    op.create_index("ix_review_tasks_status", "review_tasks", ["status"])
    op.create_index("ix_review_tasks_tenant_id", "review_tasks", ["tenant_id"])

    op.create_table(
        "task_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("task_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("queue_backend", sa.String(length=32), nullable=False, server_default="database"),
        sa.Column("backend_job_id", sa.String(length=128), nullable=True),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
        sa.Column("active_dedup_key", sa.String(length=128), nullable=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("application_id", sa.Integer(), sa.ForeignKey("applications.id"), nullable=True),
        sa.Column("environment", sa.String(length=32), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.String(length=255), nullable=True),
        sa.Column("artifact_uri", sa.String(length=512), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_retries", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("execution_log", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_task_runs_application_id", "task_runs", ["application_id"])
    op.create_index("ix_task_runs_active_dedup_key", "task_runs", ["active_dedup_key"], unique=True)
    op.create_index("ix_task_runs_backend_job_id", "task_runs", ["backend_job_id"])
    op.create_index("ix_task_runs_environment", "task_runs", ["environment"])
    op.create_index("ix_task_runs_idempotency_key", "task_runs", ["idempotency_key"])
    op.create_index("ix_task_runs_status", "task_runs", ["status"])
    op.create_index("ix_task_runs_task_type", "task_runs", ["task_type"])
    op.create_index("ix_task_runs_tenant_id", "task_runs", ["tenant_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("application_id", sa.Integer(), sa.ForeignKey("applications.id"), nullable=True),
        sa.Column("environment", sa.String(length=32), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("object_type", sa.String(length=64), nullable=True),
        sa.Column("object_id", sa.String(length=64), nullable=True),
        sa.Column("risk_type", sa.String(length=128), nullable=True),
        sa.Column("decision", sa.String(length=32), nullable=True),
        sa.Column("request_hash", sa.String(length=64), nullable=True),
        sa.Column("request_preview", sa.Text(), nullable=True),
        sa.Column("response_preview", sa.Text(), nullable=True),
        sa.Column("event_payload", sa.JSON(), nullable=True),
        sa.Column("immutable_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_application_id", "audit_logs", ["application_id"])
    op.create_index("ix_audit_logs_actor_user_id", "audit_logs", ["actor_user_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_decision", "audit_logs", ["decision"])
    op.create_index("ix_audit_logs_environment", "audit_logs", ["environment"])
    op.create_index("ix_audit_logs_event_type", "audit_logs", ["event_type"])
    op.create_index("ix_audit_logs_immutable_hash", "audit_logs", ["immutable_hash"])
    op.create_index("ix_audit_logs_object_id", "audit_logs", ["object_id"])
    op.create_index("ix_audit_logs_object_type", "audit_logs", ["object_type"])
    op.create_index("ix_audit_logs_request_hash", "audit_logs", ["request_hash"])
    op.create_index("ix_audit_logs_risk_type", "audit_logs", ["risk_type"])
    op.create_index("ix_audit_logs_tenant_id", "audit_logs", ["tenant_id"])

    op.create_table(
        "alert_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("application_id", sa.Integer(), sa.ForeignKey("applications.id"), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alert_events_application_id", "alert_events", ["application_id"])
    op.create_index("ix_alert_events_category", "alert_events", ["category"])
    op.create_index("ix_alert_events_created_at", "alert_events", ["created_at"])
    op.create_index("ix_alert_events_severity", "alert_events", ["severity"])
    op.create_index("ix_alert_events_status", "alert_events", ["status"])
    op.create_index("ix_alert_events_tenant_id", "alert_events", ["tenant_id"])


def downgrade() -> None:
    for table in [
        "alert_events",
        "audit_logs",
        "task_runs",
        "review_tasks",
        "case_records",
        "detection_results",
        "strategy_configs",
        "rules",
        "evaluation_runs",
        "samples",
        "memberships",
        "policy_bindings",
        "applications",
        "tenants",
        "role_permissions",
        "permissions",
        "roles",
        "users",
    ]:
        op.drop_table(table)
