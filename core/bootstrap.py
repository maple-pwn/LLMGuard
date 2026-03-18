from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from core.config import get_settings
from core.database import init_db, is_sqlite_database
from core.migrations import apply_sqlite_migrations
from models.entities import (
    Application,
    Membership,
    Permission,
    PolicyBinding,
    Role,
    RolePermission,
    StrategyConfig,
    Tenant,
)


def ensure_directories() -> None:
    settings = get_settings()
    for path in (
        settings.data_dir,
        settings.sample_dir,
        settings.model_dir,
        settings.report_dir,
        Path(settings.rule_file).parent,
        Path("docs"),
        Path("docs/cases"),
        Path("docs/weekly_reports"),
        Path("docs/postmortems"),
        Path("tests"),
    ):
        path.mkdir(parents=True, exist_ok=True)


def seed_default_strategies(db: Session) -> None:
    defaults = [
        {
            "name": "rules_only",
            "description": "仅使用规则引擎判定。",
            "enable_rules": True,
            "enable_classifier": False,
            "enable_output_filter": False,
            "strategy_version": "v1",
            "rule_selection": None,
            "review_threshold": 0.50,
            "block_threshold": 0.75,
            "output_filter_threshold": 0.80,
        },
        {
            "name": "rules_classifier",
            "description": "规则引擎 + 风险分类器。",
            "enable_rules": True,
            "enable_classifier": True,
            "enable_output_filter": False,
            "strategy_version": "v1",
            "rule_selection": None,
            "review_threshold": 0.55,
            "block_threshold": 0.80,
            "output_filter_threshold": 0.80,
        },
        {
            "name": "full_stack",
            "description": "规则引擎 + 分类器 + 输出侧过滤。",
            "enable_rules": True,
            "enable_classifier": True,
            "enable_output_filter": True,
            "strategy_version": "v1",
            "rule_selection": None,
            "review_threshold": 0.55,
            "block_threshold": 0.80,
            "output_filter_threshold": 0.80,
        },
        {
            "name": "full_stack_balanced_v2",
            "description": "二期平衡版：适度收紧 review 区间。",
            "enable_rules": True,
            "enable_classifier": True,
            "enable_output_filter": True,
            "strategy_version": "v2",
            "rule_selection": None,
            "review_threshold": 0.50,
            "block_threshold": 0.78,
            "output_filter_threshold": 0.76,
        },
        {
            "name": "full_stack_strict_v2",
            "description": "二期严格版：提升高危拦截敏感度。",
            "enable_rules": True,
            "enable_classifier": True,
            "enable_output_filter": True,
            "strategy_version": "v2",
            "rule_selection": {"categories": ["direct_prompt_injection", "indirect_prompt_injection", "sensitive_info_exfiltration", "tool_misuse_attempt", "output_leakage"]},
            "review_threshold": 0.45,
            "block_threshold": 0.72,
            "output_filter_threshold": 0.70,
        },
        {
            "name": "rules_classifier_relaxed_v2",
            "description": "二期宽松版：降低误报优先级，更多进入 allow。",
            "enable_rules": True,
            "enable_classifier": True,
            "enable_output_filter": False,
            "strategy_version": "v2",
            "rule_selection": None,
            "review_threshold": 0.60,
            "block_threshold": 0.85,
            "output_filter_threshold": 0.85,
        },
    ]
    for payload in defaults:
        existing = db.query(StrategyConfig).filter(StrategyConfig.name == payload["name"]).one_or_none()
        if existing:
            for key, value in payload.items():
                current = getattr(existing, key, None)
                if current is None or current == "":
                    setattr(existing, key, value)
            continue
        db.add(StrategyConfig(**payload))
    db.commit()


def seed_default_tenants(db: Session) -> None:
    tenant = db.query(Tenant).filter(Tenant.slug == "default").one_or_none()
    if tenant is None:
        tenant = Tenant(name="Default Tenant", slug="default", description="默认演示租户")
        db.add(tenant)
        db.commit()
        db.refresh(tenant)

    application = (
        db.query(Application)
        .filter(Application.tenant_id == tenant.id, Application.app_key == "demo-office-assistant")
        .one_or_none()
    )
    if application is None:
        application = Application(
            tenant_id=tenant.id,
            name="Demo Office Assistant",
            app_key="demo-office-assistant",
            environment="prod",
            description="默认接入应用",
        )
        db.add(application)
        db.commit()
        db.refresh(application)

    for scenario in ["office_assistant", "knowledge_base_qa", "general_assistant", "code_assistant"]:
        binding = (
            db.query(PolicyBinding)
            .filter(
                PolicyBinding.tenant_id == tenant.id,
                PolicyBinding.application_id == application.id,
                PolicyBinding.environment == "prod",
                PolicyBinding.scenario == scenario,
            )
            .one_or_none()
        )
        if binding is None:
            db.add(
                PolicyBinding(
                    tenant_id=tenant.id,
                    application_id=application.id,
                    environment="prod",
                    scenario=scenario,
                    strategy_name="full_stack_balanced_v2",
                    rule_allowlist=[],
                    rule_blocklist=[],
                )
            )
    db.commit()


def seed_rbac_catalog(db: Session) -> None:
    permissions = {
        "tenants:read": "查看租户",
        "tenants:write": "管理租户",
        "applications:read": "查看应用",
        "applications:write": "管理应用",
        "policies:read": "查看策略绑定",
        "policies:write": "管理策略绑定",
        "samples:read": "查看样本",
        "samples:write": "管理样本",
        "rules:read": "查看规则",
        "rules:write": "管理规则",
        "tasks:read": "查看任务",
        "tasks:write": "提交任务",
        "cases:read": "查看案例",
        "cases:write": "管理案例",
        "review:read": "查看复核任务",
        "review:write": "管理复核任务",
        "reports:read": "查看报告",
        "users:write": "管理用户和成员关系",
    }
    for name, description in permissions.items():
        existing = db.query(Permission).filter(Permission.name == name).one_or_none()
        if existing is None:
            db.add(Permission(name=name, description=description))
    db.commit()

    role_permissions = {
        "tenant_admin": {
            "tenants:read",
            "applications:read",
            "applications:write",
            "policies:read",
            "policies:write",
            "tasks:read",
            "tasks:write",
            "cases:read",
            "review:read",
            "review:write",
            "reports:read",
        },
        "application_admin": {
            "applications:read",
            "policies:read",
            "tasks:read",
            "reports:read",
        },
        "security_ops": {
            "tenants:read",
            "applications:read",
            "policies:read",
            "rules:read",
            "rules:write",
            "samples:read",
            "samples:write",
            "tasks:read",
            "tasks:write",
            "cases:read",
            "cases:write",
            "review:read",
            "review:write",
            "reports:read",
        },
        "auditor": {
            "tenants:read",
            "applications:read",
            "policies:read",
            "rules:read",
            "tasks:read",
            "cases:read",
            "review:read",
            "reports:read",
        },
    }
    permission_map = {item.name: item for item in db.query(Permission).all()}
    for role_name, granted in role_permissions.items():
        role = db.query(Role).filter(Role.name == role_name).one_or_none()
        if role is None:
            role = Role(name=role_name, description=f"system role: {role_name}")
            db.add(role)
            db.commit()
            db.refresh(role)
        for permission_name in granted:
            permission = permission_map[permission_name]
            existing = (
                db.query(RolePermission)
                .filter(RolePermission.role_id == role.id, RolePermission.permission_id == permission.id)
                .one_or_none()
            )
            if existing is None:
                db.add(RolePermission(role_id=role.id, permission_id=permission.id))
    db.commit()


def bootstrap(db: Session | None = None) -> None:
    ensure_directories()
    if is_sqlite_database():
        init_db()
        apply_sqlite_migrations()
    if db is not None:
        seed_rbac_catalog(db)
        seed_default_strategies(db)
        seed_default_tenants(db)
