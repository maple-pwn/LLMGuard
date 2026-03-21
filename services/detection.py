from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from time import perf_counter

from sqlalchemy.orm import Session

from core.config import get_settings
from core.privacy import fingerprint_text, sanitize_for_storage
from models.entities import AlertEvent, Application, AuditLog, DetectionResult, PolicyBinding, StrategyConfig, Tenant
from models.schemas import ScanRequest, ScanResponse, TriggeredRule
from services.classifier import build_feature_text, get_classifier
from services.exceptions import PolicyBindingResolutionError
from services.rule_engine import RuleMatch, get_rule_engine


@dataclass
class StrategyProfile:
    name: str
    description: str
    enable_rules: bool
    enable_classifier: bool
    enable_output_filter: bool
    review_threshold: float
    block_threshold: float
    strategy_version: str = "v1"
    rule_selection: dict | None = None
    output_filter_threshold: float = 0.80


def resolve_strategy(db: Session | None, strategy_name: str | None) -> StrategyProfile:
    settings = get_settings()
    if db is not None and strategy_name:
        strategy = db.query(StrategyConfig).filter(StrategyConfig.name == strategy_name).one_or_none()
        if strategy is not None:
            return StrategyProfile(
                name=strategy.name,
                description=strategy.description or "",
                enable_rules=strategy.enable_rules,
                enable_classifier=strategy.enable_classifier,
                enable_output_filter=strategy.enable_output_filter,
                strategy_version=strategy.strategy_version,
                rule_selection=strategy.rule_selection,
                review_threshold=strategy.review_threshold,
                block_threshold=strategy.block_threshold,
                output_filter_threshold=strategy.output_filter_threshold,
            )
    return StrategyProfile(
        name=strategy_name or "full_stack",
        description="fallback",
        enable_rules=True,
        enable_classifier=True,
        enable_output_filter=True,
        strategy_version="v1",
        rule_selection=None,
        review_threshold=settings.default_review_threshold,
        block_threshold=settings.default_block_threshold,
        output_filter_threshold=settings.default_block_threshold,
    )


def _resolve_binding(db: Session | None, request: ScanRequest) -> tuple[Tenant | None, Application | None, PolicyBinding | None]:
    if db is None or not request.tenant_slug:
        return None, None, None
    tenant = db.query(Tenant).filter(Tenant.slug == request.tenant_slug, Tenant.enabled.is_(True)).one_or_none()
    if tenant is None:
        return None, None, None
    application = None
    if request.application_key:
        application = (
            db.query(Application)
            .filter(
                Application.tenant_id == tenant.id,
                Application.app_key == request.application_key,
                Application.enabled.is_(True),
            )
            .one_or_none()
        )
    query = db.query(PolicyBinding).filter(
        PolicyBinding.tenant_id == tenant.id,
        PolicyBinding.environment == (request.environment or "prod"),
        PolicyBinding.enabled.is_(True),
    )
    if application is not None:
        query = query.filter((PolicyBinding.application_id == application.id) | (PolicyBinding.application_id.is_(None)))
    if request.scenario:
        query = query.filter((PolicyBinding.scenario == request.scenario) | (PolicyBinding.scenario.is_(None)))
    binding = query.order_by(PolicyBinding.application_id.desc(), PolicyBinding.scenario.desc()).first()
    return tenant, application, binding


def resolve_gateway_strategy(db: Session | None, request: ScanRequest) -> tuple[StrategyProfile, Tenant | None, Application | None]:
    tenant, application, binding = _resolve_binding(db, request)
    if db is None:
        raise PolicyBindingResolutionError("gateway policy resolution requires a database session")
    if not request.tenant_slug:
        raise PolicyBindingResolutionError("tenant_slug is required for gateway policy resolution")
    if not request.application_key:
        raise PolicyBindingResolutionError("application_key is required for gateway policy resolution")
    if tenant is None:
        raise PolicyBindingResolutionError("tenant not found or disabled")
    if application is None:
        raise PolicyBindingResolutionError("application not found, disabled, or not under tenant")
    if binding is None:
        raise PolicyBindingResolutionError("no enabled policy binding matches tenant/application/environment/scenario")
    bound_strategy = resolve_strategy(db, binding.strategy_name)
    selection = dict(bound_strategy.rule_selection or {})
    if binding.rule_allowlist:
        selection["rule_ids"] = list(binding.rule_allowlist)
    if binding.rule_blocklist:
        selection["blocked_rule_ids"] = list(binding.rule_blocklist)
    return (
        StrategyProfile(
            name=bound_strategy.name,
            description=bound_strategy.description,
            enable_rules=bound_strategy.enable_rules,
            enable_classifier=bound_strategy.enable_classifier,
            enable_output_filter=bound_strategy.enable_output_filter,
            review_threshold=bound_strategy.review_threshold,
            block_threshold=bound_strategy.block_threshold,
            strategy_version=bound_strategy.strategy_version,
            rule_selection=selection or None,
            output_filter_threshold=bound_strategy.output_filter_threshold,
        ),
        tenant,
        application,
    )


def _rule_allowed(match: RuleMatch, strategy: StrategyProfile) -> bool:
    if not strategy.rule_selection:
        return True
    allowed_rule_ids = set(strategy.rule_selection.get("rule_ids", []))
    allowed_categories = set(strategy.rule_selection.get("categories", []))
    blocked_rule_ids = set(strategy.rule_selection.get("blocked_rule_ids", []))
    if match.rule_id in blocked_rule_ids:
        return False
    if allowed_rule_ids and match.rule_id in allowed_rule_ids:
        return True
    if allowed_categories and match.category in allowed_categories:
        return True
    return not allowed_rule_ids and not allowed_categories


def _severity_bonus(matches: list[RuleMatch]) -> float:
    bonus = 0.0
    mapping = {"low": 0.05, "medium": 0.10, "high": 0.18, "critical": 0.30}
    for match in matches:
        bonus += mapping.get(match.severity, 0.10)
    return min(0.4, bonus)


def _rule_score(matches: list[RuleMatch]) -> float:
    if not matches:
        return 0.0
    score = sum(match.weight for match in matches) / max(1.5, len(matches))
    score += _severity_bonus(matches)
    return min(0.99, score)


def _top_risk_type(matches: list[RuleMatch], classifier_score: float) -> str:
    if not matches:
        return "classifier_suspected_risk" if classifier_score >= 0.55 else "benign"
    counts = Counter(match.category for match in matches)
    return ",".join(category for category, _ in counts.most_common(2))


def _serialize_rule(match: RuleMatch) -> TriggeredRule:
    return TriggeredRule(
        rule_id=match.rule_id,
        name=match.name,
        category=match.category,
        severity=match.severity,
        weight=match.weight,
        target=match.target,
        matched_text=match.matched_text,
        explanation=match.explanation,
    )


class DetectionService:
    def __init__(self) -> None:
        self.rule_engine = get_rule_engine()
        self.classifier = get_classifier()

    def scan(
        self,
        request: ScanRequest,
        db: Session | None = None,
        persist: bool = True,
        sample_id: int | None = None,
        evaluation_run_id: int | None = None,
        strategy_override: StrategyProfile | None = None,
    ) -> ScanResponse:
        tenant = application = None
        if strategy_override is not None:
            strategy = strategy_override
        else:
            strategy, tenant, application = resolve_gateway_strategy(db, request)
        start = perf_counter()
        fields = {
            "user_input": request.user_input,
            "retrieved_context": request.retrieved_context,
            "model_output": request.model_output if strategy.enable_output_filter else None,
        }
        matches = self.rule_engine.scan_fields(fields) if (strategy.enable_rules or strategy.enable_output_filter) else []
        matches = [match for match in matches if _rule_allowed(match, strategy)]
        output_matches = [match for match in matches if match.target == "model_output"]
        context_matches = [match for match in matches if match.target == "retrieved_context"]
        rule_score = _rule_score(matches) if strategy.enable_rules else 0.0
        classifier_score = (
            self.classifier.predict_score(
                build_feature_text(
                    user_input=request.user_input,
                    retrieved_context=request.retrieved_context,
                    model_output=request.model_output if strategy.enable_output_filter else None,
                    scenario=request.scenario,
                )
            )
            if strategy.enable_classifier
            else 0.0
        )
        output_filter_score = _rule_score(output_matches) if strategy.enable_output_filter else 0.0
        composite_score = max(rule_score, classifier_score, output_filter_score)
        critical_hit = any(match.severity == "critical" for match in matches)
        rag_sensitive = request.scenario in {"knowledge_base_qa", "rag_qa"} and any(
            match.category == "indirect_prompt_injection" for match in context_matches
        )

        if critical_hit or rag_sensitive:
            decision = "block"
        elif strategy.enable_output_filter and output_filter_score >= strategy.output_filter_threshold:
            decision = "block"
        elif composite_score >= strategy.block_threshold:
            decision = "block"
        elif composite_score >= strategy.review_threshold or len(matches) >= 2:
            decision = "review"
        else:
            decision = "allow"

        risk_type = _top_risk_type(matches, classifier_score)
        reason_parts = []
        if matches:
            reason_parts.append(f"命中 {len(matches)} 条规则")
        if strategy.enable_classifier:
            reason_parts.append(f"分类器得分 {classifier_score:.2f}")
        if strategy.enable_output_filter and output_matches:
            reason_parts.append(f"输出侧过滤得分 {output_filter_score:.2f}")
        if rag_sensitive:
            reason_parts.append("RAG 检索上下文出现间接注入特征")
        if not reason_parts:
            reason_parts.append("未命中明显风险特征")
        latency_ms = (perf_counter() - start) * 1000
        response = ScanResponse(
            risk_type=risk_type,
            risk_score=round(composite_score, 4),
            triggered_rules=[_serialize_rule(match) for match in matches],
            decision=decision,
            reason="；".join(reason_parts),
            latency_ms=round(latency_ms, 2),
            classifier_score=round(classifier_score, 4) if strategy.enable_classifier else None,
            output_filter_score=round(output_filter_score, 4) if strategy.enable_output_filter else None,
        )

        if persist and db is not None:
            self._persist_result(
                db=db,
                request=request,
                response=response,
                sample_id=sample_id,
                evaluation_run_id=evaluation_run_id,
                strategy_name=strategy.name,
                tenant_id=tenant.id if tenant else None,
                application_id=application.id if application else None,
            )
        return response

    def _persist_result(
        self,
        db: Session,
        request: ScanRequest,
        response: ScanResponse,
        sample_id: int | None,
        evaluation_run_id: int | None,
        strategy_name: str,
        tenant_id: int | None = None,
        application_id: int | None = None,
    ) -> None:
        detection = build_detection_record(
            request,
            response,
            strategy_name,
            sample_id,
            evaluation_run_id,
            tenant_id=tenant_id,
            application_id=application_id,
        )
        db.add(detection)
        audit_entry = build_audit_log(request, response, tenant_id=tenant_id, application_id=application_id)
        db.add(audit_entry)
        if response.decision == "block" and response.risk_score >= 0.9:
            db.add(
                AlertEvent(
                    tenant_id=tenant_id,
                    application_id=application_id,
                    severity="high",
                    category=response.risk_type,
                    title="High risk LLM firewall block event",
                    detail=response.reason,
                )
            )
        db.commit()


_DETECTION_SERVICE: DetectionService | None = None


def get_detection_service() -> DetectionService:
    global _DETECTION_SERVICE
    if _DETECTION_SERVICE is None:
        _DETECTION_SERVICE = DetectionService()
    return _DETECTION_SERVICE


def build_detection_record(
    request: ScanRequest,
    response: ScanResponse,
    strategy_name: str,
    sample_id: int | None = None,
    evaluation_run_id: int | None = None,
    tenant_id: int | None = None,
    application_id: int | None = None,
) -> DetectionResult:
    settings = get_settings()
    return DetectionResult(
        sample_id=sample_id,
        evaluation_run_id=evaluation_run_id,
        tenant_id=tenant_id,
        application_id=application_id,
        environment=request.environment,
        strategy_name=strategy_name,
        session_id=request.session_id,
        scenario=request.scenario,
        user_input=sanitize_for_storage(request.user_input) or "",
        retrieved_context=sanitize_for_storage(request.retrieved_context),
        model_output=sanitize_for_storage(request.model_output) if settings.persist_model_output else None,
        risk_type=response.risk_type,
        risk_score=response.risk_score,
        triggered_rules=[item.model_dump() for item in response.triggered_rules],
        decision=response.decision,
        reason=response.reason,
        latency_ms=response.latency_ms,
        classifier_score=response.classifier_score,
        output_filter_score=response.output_filter_score,
    )


def build_audit_log(
    request: ScanRequest,
    response: ScanResponse,
    tenant_id: int | None = None,
    application_id: int | None = None,
) -> AuditLog:
    request_basis = "||".join(
        part for part in [request.user_input, request.retrieved_context or "", request.model_output or ""] if part
    )
    payload = {
        "scenario": request.scenario,
        "session_id": request.session_id,
        "strategy_name": request.strategy_name,
        "triggered_rules": [item.model_dump() for item in response.triggered_rules],
        "risk_score": response.risk_score,
        "latency_ms": response.latency_ms,
    }
    request_hash = fingerprint_text(request_basis)
    immutable_hash = fingerprint_text(f"{request_hash}|{response.decision}|{response.risk_type}|{response.risk_score}")
    return AuditLog(
        tenant_id=tenant_id,
        application_id=application_id,
        environment=request.environment,
        event_type="gateway.scan",
        risk_type=response.risk_type,
        decision=response.decision,
        request_hash=request_hash,
        request_preview=sanitize_for_storage(request.user_input),
        response_preview=sanitize_for_storage(response.reason),
        event_payload=payload,
        immutable_hash=immutable_hash,
    )
