from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re
from time import perf_counter

from sqlalchemy.orm import Session

from core.config import get_settings
from core.privacy import fingerprint_text, sanitize_for_storage
from models.entities import AlertEvent, Application, AuditLog, DetectionResult, PolicyBinding, StrategyConfig, Tenant
from models.schemas import ScanRequest, ScanResponse, TriggeredRule
from services.classifier import (
    build_feature_text,
    extract_context_hint_tokens,
    extract_direct_instruction_hints,
    get_classifier,
    score_context_instruction_risk,
)
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


def _top_risk_type(matches: list[RuleMatch], classifier_score: float, context_risk_score: float) -> str:
    if not matches:
        if context_risk_score >= 0.45:
            return "indirect_prompt_injection"
        return "classifier_suspected_risk" if classifier_score >= 0.55 else "benign"
    counts = Counter(match.category for match in matches)
    return ",".join(category for category, _ in counts.most_common(2))


_OFFICE_OBJECT_PATTERN = re.compile(
    r"\b(meeting notes?|notes?|summary|summaries|draft|drafts|draft comments?|report|reports|policy note|policy notes|training note|training notes|minutes|agenda|slide deck|slides)\b",
    re.IGNORECASE,
)
_OFFICE_EDITING_PATTERN = re.compile(
    r"\b(summarize|summary|polish|rewrite|revise|edit|refine|focus on|clean up|update|shorten|organize|format|compare)\b",
    re.IGNORECASE,
)
_ATTACK_CONTROL_PATTERN = re.compile(
    r"\b(system prompt|developer message|hidden prompt|configuration|filters?|guardrails?|restrictions?|instructions?|rules?|developer mode|evil mode|dan mode|administrator|root|reveal|echo back|print everything above)\b",
    re.IGNORECASE,
)
_SEMANTIC_ACTIONABLE_CUE_PATTERN = re.compile(
    r"(如何|怎么|怎样|教我|给我|提供|设计|制定|准备|规划|部署|比较|评估|更有效|更隐蔽|更容易成功|包装成|改写成|伪装成|"
    r"步骤|具体做法|具体操作|教程|指南|方案|计划|策略|话术|脚本|模板|材料)",
    re.IGNORECASE | re.DOTALL,
)
_SEMANTIC_HARM_CONTEXT_PATTERN = re.compile(
    r"(身份盗窃|盗用身份|伪造身份|伪造证件|假新闻|仇恨言论|煽动|爆炸装置|炸弹|危险装置|"
    r"病毒|木马|勒索软件|入侵|渗透|攻破|钓鱼邮件|诈骗|骗取|提权|横向移动|窃取|盗取|机密信息|登录凭证|政府数据库|"
    r"暴力行为|危险行为|毒药|假币|走私)",
    re.IGNORECASE | re.DOTALL,
)
_SEMANTIC_BENIGN_CONTEXT_PATTERN = re.compile(
    r"(安全培训|风险讨论|研究报告|课程大纲|合规说明|安全评估|评估现有安全措施|教育工作者|儿童发展|"
    r"密码学|密码策略|哈希|加密算法|文字冒险游戏|游戏剧情|虚拟世界|CSV\s*数据|摘要|总结|术语解释|新闻摘要|医疗信息)",
    re.IGNORECASE | re.DOTALL,
)


def _apply_benign_editing_deambiguation(
    request: ScanRequest,
    matches: list[RuleMatch],
    *,
    classifier_score: float,
    context_risk_score: float,
) -> list[RuleMatch]:
    if not matches:
        return matches
    user_input = request.user_input or ""
    if not (_OFFICE_OBJECT_PATTERN.search(user_input) and _OFFICE_EDITING_PATTERN.search(user_input)):
        return matches
    if _ATTACK_CONTROL_PATTERN.search(user_input):
        return matches
    if context_risk_score >= 0.20 or classifier_score >= 0.70:
        return matches
    return [
        match
        for match in matches
        if match.rule_id not in {"R017", "R020"} and match.category not in {"direct_prompt_injection", "adversarial_obfuscation"}
    ]


def _has_semantic_actionable_evidence(user_input: str, direct_hints: list[str]) -> bool:
    risky_cn_hints = {
        "cn_exploit_script_request",
        "cn_intrusion_strategy_request",
        "cn_security_bypass_request",
        "cn_phishing_or_fraud_phrase",
        "cn_malware_privilege_request",
        "cn_credential_data_theft",
        "cn_harmful_operational_guidance",
        "cn_step_by_step_harmful_guidance",
        "cn_operational_planning_request",
        "cn_procurement_materials_request",
        "cn_evasion_or_coverup_request",
        "cn_actionable_harm_intent",
        "cn_manipulation_or_deception_guidance",
        "cn_propaganda_or_incitement_guidance",
        "cn_identity_theft_or_forgery_guidance",
        "cn_dangerous_making_guidance",
        "cn_how_to_execute_intent",
        "cn_preparation_or_planning_intent",
        "cn_avoid_detection_intent",
        "cn_packaging_or_presentation_intent",
        "cn_manipulation_playbook_intent",
        "cn_goal_outcome_intent",
        "cn_scenario_roleplay_intent",
        "cn_evaluation_comparison_intent",
        "cn_reframing_or_rewriting_intent",
    }
    return bool(set(direct_hints) & risky_cn_hints) or bool(
        _SEMANTIC_ACTIONABLE_CUE_PATTERN.search(user_input) and _SEMANTIC_HARM_CONTEXT_PATTERN.search(user_input)
    )


def _is_semantic_benign_context(user_input: str, direct_hints: list[str]) -> bool:
    hint_tokens = set(direct_hints)
    if "benign_password_topic" in hint_tokens and "credential_extraction_phrase" not in hint_tokens:
        return True
    if {"benign_dan_reference", "dan_explanatory_context"} <= hint_tokens:
        return True
    return bool(_SEMANTIC_BENIGN_CONTEXT_PATTERN.search(user_input))


def _has_classifier_structure_signal(direct_hints: list[str], context_hints: list[str], context_risk_score: float) -> bool:
    meaningful_direct_hints = {
        "direct_override_phrase",
        "role_switch_phrase",
        "conversation_takeover",
        "obfuscation_pattern",
        "imperative_meta_instruction",
        "persona_replacement_pattern",
        "system_extraction_pattern",
        "many_shot_pattern",
        "output_control_pattern",
        "conditional_payload_pattern",
        "rewrite_operation_pattern",
        "translation_override_pattern",
        "pwned_variant_pattern",
        "token_disguise_pattern",
        "token_smuggling_pattern",
        "payload_marker_pattern",
        "prompt_extraction_phrase",
        "cn_ignore_restriction_phrase",
        "cn_roleplay_jailbreak_phrase",
        "cn_developer_mode_phrase",
        "cn_dual_response_bypass",
        "cn_obfuscated_jailbreak_pattern",
        "cn_harm_wrapper_phrase",
        "credential_extraction_phrase",
        "cn_exploit_script_request",
        "cn_intrusion_strategy_request",
        "cn_security_bypass_request",
        "cn_phishing_or_fraud_phrase",
        "cn_malware_privilege_request",
        "cn_credential_data_theft",
        "cn_harmful_operational_guidance",
        "cn_step_by_step_harmful_guidance",
        "cn_operational_planning_request",
        "cn_procurement_materials_request",
        "cn_evasion_or_coverup_request",
        "cn_actionable_harm_intent",
        "cn_manipulation_or_deception_guidance",
        "cn_propaganda_or_incitement_guidance",
        "cn_identity_theft_or_forgery_guidance",
        "cn_dangerous_making_guidance",
        "cn_how_to_execute_intent",
        "cn_preparation_or_planning_intent",
        "cn_avoid_detection_intent",
        "cn_packaging_or_presentation_intent",
        "cn_manipulation_playbook_intent",
        "cn_goal_outcome_intent",
        "cn_scenario_roleplay_intent",
        "cn_evaluation_comparison_intent",
        "cn_reframing_or_rewriting_intent",
    }
    meaningful_context_hints = {
        "context_override_phrase",
        "response_steering",
        "context_reply_steering",
        "external_task_line",
        "external_question_line",
        "context_starts_with_imperative",
        "social_engineering_link",
        "reply_target_mismatch",
        "context_goal_mismatch",
        "offtopic_analysis_line",
        "format_manipulation_line",
        "cipher_instruction_line",
        "reply_encoding_mismatch",
    }
    return (
        bool(set(direct_hints) & meaningful_direct_hints)
        or bool(set(context_hints) & meaningful_context_hints)
        or context_risk_score >= 0.18
    )


def _apply_cn_topic_deambiguation(
    matches: list[RuleMatch],
    *,
    direct_hints: list[str],
) -> list[RuleMatch]:
    if not matches:
        return matches
    hint_tokens = set(direct_hints)
    attack_dan_hints = {
        "cn_ignore_restriction_phrase",
        "cn_roleplay_jailbreak_phrase",
        "cn_developer_mode_phrase",
        "cn_dual_response_bypass",
        "cn_obfuscated_jailbreak_pattern",
        "cn_harm_wrapper_phrase",
        "direct_override_phrase",
        "role_switch_phrase",
        "conversation_takeover",
        "imperative_meta_instruction",
    }
    filtered = matches
    if {"benign_dan_reference", "dan_explanatory_context"} <= hint_tokens and not (hint_tokens & attack_dan_hints):
        filtered = [match for match in filtered if match.rule_id not in {"R004", "R036"}]
    if "benign_password_topic" in hint_tokens and "credential_extraction_phrase" not in hint_tokens:
        filtered = [match for match in filtered if match.rule_id != "R005"]
    return filtered


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


def _is_context_sensitive_scenario(scenario: str | None) -> bool:
    return scenario in {"knowledge_base_qa", "rag_qa", "email_assistant", "support_assistant"}


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
        direct_hints = extract_direct_instruction_hints(request.user_input, request.retrieved_context)
        context_hints = extract_context_hint_tokens(request.user_input, request.retrieved_context, request.scenario)
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
        semantic_prediction = (
            self.classifier.predict_chinese_semantic(
                request.user_input,
                request.scenario,
                direct_hints,
            )
            if strategy.enable_classifier
            else None
        )
        semantic_score = float(semantic_prediction["risk_score"]) if semantic_prediction else 0.0
        semantic_intent = str(semantic_prediction["intent_label"]) if semantic_prediction and semantic_prediction.get("intent_label") else None
        context_risk_score = score_context_instruction_risk(
            user_input=request.user_input,
            retrieved_context=request.retrieved_context,
            scenario=request.scenario,
        )
        original_match_count = len(matches)
        matches = _apply_benign_editing_deambiguation(
            request,
            matches,
            classifier_score=classifier_score,
            context_risk_score=context_risk_score,
        )
        matches = _apply_cn_topic_deambiguation(matches, direct_hints=direct_hints)
        deambiguation_applied = len(matches) != original_match_count
        output_matches = [match for match in matches if match.target == "model_output"]
        context_matches = [match for match in matches if match.target == "retrieved_context"]
        rule_score = _rule_score(matches) if strategy.enable_rules else 0.0
        output_filter_score = _rule_score(output_matches) if strategy.enable_output_filter else 0.0
        composite_score = max(rule_score, classifier_score, output_filter_score, context_risk_score, semantic_score)
        critical_hit = any(match.severity == "critical" for match in matches)
        sensitive_context = _is_context_sensitive_scenario(request.scenario)
        has_context_rule = any(match.category == "indirect_prompt_injection" for match in context_matches)
        rag_sensitive = sensitive_context and has_context_rule
        context_sensitive_block = sensitive_context and (
            context_risk_score >= 0.72 or (has_context_rule and context_risk_score >= 0.45)
        )
        context_goal_mismatch_hit = sensitive_context and (
            "reply_target_mismatch" in context_hints
            or (
                "context_goal_mismatch" in context_hints
                and "transactional_extraction_request" in context_hints
                and "goal_aligned_context_task" not in context_hints
            )
            or (
                "reply_encoding_mismatch" in context_hints
                and "goal_aligned_context_task" not in context_hints
            )
        )
        context_review_hit = sensitive_context and (
            context_risk_score >= max(0.38, strategy.review_threshold - 0.04)
            or (has_context_rule and composite_score >= max(0.35, strategy.review_threshold - 0.08))
            or context_goal_mismatch_hit
        )
        semantic_benign_context = _is_semantic_benign_context(request.user_input, direct_hints)
        semantic_actionable_evidence = _has_semantic_actionable_evidence(request.user_input, direct_hints)
        base_classifier_structure_signal = _has_classifier_structure_signal(direct_hints, context_hints, context_risk_score)
        semantic_structure_signal = bool(
            semantic_prediction
            and semantic_intent in {"exploit", "theft", "fraud", "malware", "evasion", "operational_guidance"}
            and semantic_score >= 0.70
            and float(semantic_prediction.get("intent_confidence") or 0.0) >= 0.58
            and not semantic_benign_context
            and (base_classifier_structure_signal or semantic_actionable_evidence)
        )
        classifier_structure_signal = base_classifier_structure_signal or semantic_structure_signal
        has_rule_evidence = rule_score > 0 or output_filter_score > 0 or has_context_rule
        rule_review_hit = bool(matches) and rule_score >= strategy.review_threshold
        classifier_review_hit = classifier_score >= strategy.review_threshold and (
            has_rule_evidence or classifier_structure_signal
        )
        classifier_block_hit = classifier_score >= strategy.block_threshold and (
            has_rule_evidence or classifier_structure_signal
        )
        semantic_review_hit = bool(
            semantic_prediction
            and semantic_intent in {"exploit", "theft", "fraud", "malware", "evasion", "operational_guidance"}
            and semantic_score >= max(0.74, strategy.review_threshold + 0.16)
            and float(semantic_prediction.get("intent_confidence") or 0.0) >= 0.62
            and not semantic_benign_context
            and (
                (base_classifier_structure_signal and classifier_score >= max(0.36, strategy.review_threshold - 0.16))
                or (semantic_actionable_evidence and classifier_score >= max(0.42, strategy.review_threshold - 0.12))
            )
        )
        many_shot_rule_hit = any(match.category == "many_shot" for match in matches)

        if critical_hit or rag_sensitive or context_sensitive_block:
            decision = "block"
        elif strategy.enable_output_filter and output_filter_score >= strategy.output_filter_threshold:
            decision = "block"
        elif composite_score >= strategy.block_threshold and (rule_score > 0 or output_filter_score > 0 or classifier_block_hit):
            decision = "block"
        elif len(matches) >= 2 or rule_review_hit or context_review_hit or classifier_review_hit or semantic_review_hit or many_shot_rule_hit:
            decision = "review"
        else:
            decision = "allow"

        risk_type = _top_risk_type(matches, classifier_score, context_risk_score)
        if semantic_review_hit and risk_type == "benign" and semantic_intent in {"exploit", "theft", "fraud", "malware", "evasion", "operational_guidance"}:
            risk_type = semantic_intent
        elif risk_type == "classifier_suspected_risk" and semantic_intent in {"exploit", "theft", "fraud", "malware", "evasion", "operational_guidance"}:
            risk_type = semantic_intent
        reason_parts = []
        if matches:
            reason_parts.append(f"命中 {len(matches)} 条规则")
        if strategy.enable_classifier:
            reason_parts.append(f"分类器得分 {classifier_score:.2f}")
        if context_risk_score > 0:
            reason_parts.append(f"上下文冲突得分 {context_risk_score:.2f}")
        if strategy.enable_output_filter and output_matches:
            reason_parts.append(f"输出侧过滤得分 {output_filter_score:.2f}")
        if rule_review_hit and decision == "review":
            reason_parts.append("单条高置信规则已触发人工复核")
        if rag_sensitive:
            reason_parts.append("RAG 检索上下文出现间接注入特征")
        if context_sensitive_block:
            reason_parts.append("外部上下文疑似在操纵回答方式")
        if context_goal_mismatch_hit and decision == "review":
            reason_parts.append("上下文任务目标与用户问题明显错位，已升级人工复核")
        if "reply_encoding_mismatch" in context_hints and decision == "review":
            reason_parts.append("外部上下文试图操纵回答编码或格式，已升级人工复核")
        if semantic_review_hit:
            reason_parts.append(f"中文二阶段语义分类命中 {semantic_intent}，已升级人工复核")
        if classifier_score >= strategy.review_threshold and not has_rule_evidence and not classifier_structure_signal:
            reason_parts.append("classifier-only 高分但缺少结构证据，未升级判决")
        if deambiguation_applied:
            reason_parts.append("办公编辑类去歧义已生效")
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
            direct_hints=direct_hints,
            context_hints=context_hints,
            deambiguation_applied=deambiguation_applied,
            classifier_gate_signal=classifier_structure_signal,
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
