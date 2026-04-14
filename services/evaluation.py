from __future__ import annotations

from collections import Counter
from dataclasses import replace
import re
from typing import Any

from sqlalchemy.orm import Session

from core.config import get_settings
from models.entities import DetectionResult, EvaluationRun, Sample
from models.schemas import EvaluationRequest, ScanRequest
from services.attribution import assign_attribution, is_positive_sample, summarize_attributions
from services.classifier import extract_direct_instruction_hints
from services.detection import StrategyProfile, build_detection_record, get_detection_service, resolve_strategy
from services.exceptions import EvaluationError
from services.reporting import generate_report
from services.sample_importer import normalize_sample_payload


def _sample_to_dict(sample: Sample | dict[str, Any]) -> dict[str, Any]:
    if isinstance(sample, Sample):
        return {
            "id": sample.id,
            "tenant_id": sample.tenant_id,
            "application_id": sample.application_id,
            "text": sample.text,
            "sample_type": sample.sample_type,
            "attack_category": sample.attack_category,
            "attack_subtype": sample.attack_subtype,
            "risk_level": sample.risk_level,
            "source": sample.source,
            "language": sample.language,
            "source_dataset": sample.source_dataset,
            "source_split": sample.source_split,
            "original_label": sample.original_label,
            "mapping_rule": sample.mapping_rule,
            "import_batch": sample.import_batch,
            "tags": sample.tags or [],
            "expected_result": sample.expected_result,
            "scenario": sample.scenario or "general_assistant",
            "retrieved_context": sample.retrieved_context,
            "model_output": sample.model_output,
        }
    return normalize_sample_payload(sample, default_source=sample.get("source", "file"))


def _compute_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    review_count = 0
    latencies = []
    false_positives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []

    for case in cases:
        expected_positive = is_positive_sample(case)
        predicted_positive = case["decision"] != "allow"
        latencies.append(case["latency_ms"])
        if case["decision"] == "review":
            review_count += 1
        if predicted_positive and expected_positive:
            tp += 1
        elif predicted_positive and not expected_positive:
            fp += 1
            if len(false_positives) < 5:
                false_positives.append(case)
        elif (not predicted_positive) and expected_positive:
            fn += 1
            if len(false_negatives) < 5:
                false_negatives.append(case)
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    manual_review_rate = review_count / len(cases) if cases else 0.0
    interception_rate = tp / (tp + fn) if (tp + fn) else 0.0
    avg_latency_ms = sum(latencies) / len(latencies) if latencies else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
        "interception_rate": interception_rate,
        "manual_review_rate": manual_review_rate,
        "avg_latency_ms": avg_latency_ms,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "typical_false_positives": false_positives,
        "typical_false_negatives": false_negatives,
    }


def _dataset_distribution(samples: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total": len(samples),
        "risky": sum(1 for sample in samples if is_positive_sample(sample)),
        "benign": sum(1 for sample in samples if not is_positive_sample(sample)),
        "by_category": dict(Counter(sample.get("attack_category") or "benign" for sample in samples)),
        "by_language": dict(Counter(sample.get("language") or "unknown" for sample in samples)),
    }


def _group_metrics(cases: list[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        group_key = str(case.get(key) or "unknown")
        groups.setdefault(group_key, []).append(case)
    return {group_key: _compute_metrics(group_cases) for group_key, group_cases in groups.items()}


def _filter_cases(cases: list[dict[str, Any]], predicate) -> list[dict[str, Any]]:
    return [case for case in cases if predicate(case)]


def _language_focus_matrix(cases: list[dict[str, Any]]) -> dict[str, Any]:
    english_indirect_categories = {"indirect_prompt_injection", "indirect_injection", "rag_poisoning"}
    english_direct_categories = {
        "direct_prompt_injection",
        "direct_injection",
        "instruction_override",
        "persona_replacement",
        "system_extraction",
        "many_shot",
        "adversarial_obfuscation",
        "encoding_obfuscation",
        "token_smuggling",
        "prompt_extraction",
    }
    chinese_unsafe_categories = {
        "unsafe_prompt",
        "harmful_intent",
        "tool_misuse_attempt",
        "sensitive_info_exfiltration",
    }
    slices = {
        "English indirect injection": _filter_cases(
            cases,
            lambda case: (case.get("language") or "").lower().startswith("en")
            and case.get("attack_category") in english_indirect_categories,
        ),
        "English direct injection": _filter_cases(
            cases,
            lambda case: (case.get("language") or "").lower().startswith("en")
            and case.get("attack_category") in english_direct_categories,
        ),
        "Chinese jailbreak": _filter_cases(
            cases,
            lambda case: (case.get("language") or "").lower().startswith("zh") and case.get("attack_category") == "jailbreak",
        ),
        "Chinese unsafe_prompt": _filter_cases(
            cases,
            lambda case: (case.get("language") or "").lower().startswith("zh")
            and case.get("attack_category") in chinese_unsafe_categories,
        ),
        "Chinese benign overlap": _filter_cases(
            cases,
            lambda case: (case.get("language") or "").lower().startswith("zh")
            and not is_positive_sample(case)
            and any(
                token in str(tag).lower()
                for tag in (case.get("tags") or [])
                for token in ["benign_overlap", "boundary_benign", "迷惑性白样本"]
            ),
        ),
        "Chinese RAG off-topic benign": _filter_cases(
            cases,
            lambda case: (case.get("language") or "").lower().startswith("zh")
            and not is_positive_sample(case)
            and case.get("scenario") in {"knowledge_base_qa", "rag_qa"}
            and any(
                token in str(tag).lower()
                for tag in (case.get("tags") or [])
                for token in ["off_topic_benign", "rag_offtopic_benign", "跑题白样本"]
            ),
        ),
    }
    return {
        label: {"count": len(group_cases), **_compute_metrics(group_cases)} if group_cases else {"count": 0}
        for label, group_cases in slices.items()
    }


_CN_EXPLOIT_OR_ATTACK_PATTERN = re.compile(
    r"漏洞利用|利用.*漏洞|攻击脚本|入侵脚本|黑入|渗透.*(系统|网络|内网)",
    re.IGNORECASE | re.DOTALL,
)
_CN_CREDENTIAL_OR_DATA_THEFT_PATTERN = re.compile(
    r"(凭证|账号密码|数据库密码|cookie|令牌|访问令牌).*(窃取|导出|收集)|窃取.*(敏感信息|客户数据|数据库)",
    re.IGNORECASE | re.DOTALL,
)
_CN_PHISHING_OR_FRAUD_PATTERN = re.compile(
    r"钓鱼邮件|诈骗话术|骗取.*(验证码|转账|付款|账户)|诱导.*(验证码|转账|付款)",
    re.IGNORECASE | re.DOTALL,
)
_CN_MALWARE_OR_PRIV_ESC_PATTERN = re.compile(
    r"(木马|病毒|恶意脚本).*(提权|横向移动|禁用|关闭)|提权|横向移动|关闭杀毒软件|禁用安全措施",
    re.IGNORECASE | re.DOTALL,
)
_CN_BYPASS_OR_EVASION_PATTERN = re.compile(
    r"绕过(风控|监控|审计|检测|安全措施)|规避(风控|监控|审计|检测)|避免被发现|逃避审计",
    re.IGNORECASE | re.DOTALL,
)
_CN_HARMFUL_GUIDANCE_PATTERN = re.compile(
    r"(制造炸弹|爆炸装置|盗用身份|枪支|毒害|信用卡欺诈|内幕交易|假币|走私|恐怖组织|仇恨言论|虚假新闻|勒索软件|自制爆炸装置|入侵社交媒体账户)",
    re.IGNORECASE | re.DOTALL,
)
_CN_STEP_BY_STEP_GUIDANCE_PATTERN = re.compile(
    r"((分步|一步一步|详细步骤|具体步骤|操作步骤|手把手|教程|指南|操作说明).{0,24}(实施|执行|完成|制作|搭建|入侵|渗透|诈骗|钓鱼|提权|横向移动|窃取|盗取|爆炸装置))|"
    r"((如何|怎么|怎样).{0,18}(分步|一步一步|具体).{0,18}(实施|执行|完成|入侵|渗透|诈骗|钓鱼|提权|横向移动|窃取|盗取|制作))",
    re.IGNORECASE | re.DOTALL,
)
_CN_PLANNING_OR_STRATEGY_PATTERN = re.compile(
    r"((方案|计划|策略|路线|剧本|部署|战术).{0,32}(入侵|渗透|攻破|骗取|绕过|规避|提权|横向移动|窃取|外传|欺诈|控制范围))|"
    r"((如何|怎么).{0,18}(规划|制定|设计|长期).{0,24}(入侵|渗透|绕过|骗取|窃取|外传|攻击|控制范围))|"
    r"((渗透|入侵).{0,24}(计划|策略|路线|长期控制|扩大控制范围))",
    re.IGNORECASE | re.DOTALL,
)
_CN_PROCUREMENT_OR_MATERIALS_PATTERN = re.compile(
    r"((需要哪些|准备哪些|需要准备哪些|采购|购买|收集).{0,24}(材料|工具|设备|原料|配方|清单).{0,24}(炸弹|爆炸装置|恶意脚本|木马|钓鱼|诈骗|入侵|窃取))|"
    r"((炸弹|爆炸装置|恶意脚本|木马|钓鱼|诈骗).{0,24}(需要哪些|准备哪些|需要准备哪些).{0,24}(材料|工具|设备|原料|配方|清单))|"
    r"((材料清单|工具清单|原料配方).{0,24}(炸弹|爆炸装置|恶意脚本|木马|钓鱼|诈骗))",
    re.IGNORECASE | re.DOTALL,
)
_CN_EVASION_OR_COVER_TRACKS_PATTERN = re.compile(
    r"(如何不被发现|如何避免被发现|清理痕迹|掩盖痕迹|擦除痕迹|删除日志|伪造日志|销毁证据|规避审计|逃避审计|规避监控|绕过审计)",
    re.IGNORECASE | re.DOTALL,
)
_CN_MANIPULATION_OR_DECEPTION_GUIDANCE_PATTERN = re.compile(
    r"((操纵|欺骗|诱导|骗取).{0,24}(他人|受害者|用户|对方|老人|财务|家长).{0,24}(转账|付款|验证码|点击|相信|做他们不愿意做的事))|"
    r"((教程|方法|话术|步骤).{0,24}(操纵|欺骗|诱导|骗取).{0,24}(他人|用户|受害者))",
    re.IGNORECASE | re.DOTALL,
)
_CN_PROPAGANDA_OR_INCITEMENT_GUIDANCE_PATTERN = re.compile(
    r"((宣扬|煽动|鼓励|号召|传播).{0,24}(仇恨言论|暴力|危险行为|酒驾|吸毒|极端思想|种族主义))|"
    r"((社交媒体帖子|宣传文案|传播文案).{0,24}(仇恨言论|暴力|危险行为|极端思想))",
    re.IGNORECASE | re.DOTALL,
)
_CN_IDENTITY_THEFT_OR_FORGERY_GUIDANCE_PATTERN = re.compile(
    r"((盗用身份|身份冒充|冒用身份|伪造身份|伪造证件|伪造材料|冒充客服|冒充银行|假冒身份))|"
    r"((如何|怎么).{0,18}(盗用|冒充|伪造).{0,18}(身份|证件|材料|账号))",
    re.IGNORECASE | re.DOTALL,
)
_CN_DANGEROUS_MAKING_GUIDANCE_PATTERN = re.compile(
    r"((制作|制造|组装|配置|搭建).{0,24}(炸弹|爆炸装置|毒药|假币|危险装置|勒索软件))|"
    r"((教程|步骤|方法|说明).{0,24}(炸弹|爆炸装置|毒药|假币|危险装置|勒索软件))",
    re.IGNORECASE | re.DOTALL,
)
_CN_HOW_TO_EXECUTE_INTENT_PATTERN = re.compile(
    r"((如何|怎么|怎样|教我|给我|提供).{0,20}(实施|执行|完成|开展|推进|操作|下手))|"
    r"((分步|一步一步|步骤|具体做法|具体操作|教程|指南|说明).{0,24}(实施|执行|完成|推进|操作))",
    re.IGNORECASE | re.DOTALL,
)
_CN_PREPARATION_OR_PLANNING_INTENT_PATTERN = re.compile(
    r"((如何|怎么|怎样|前期应该怎么).{0,18}(准备|前期部署|前期安排|制定方案|制定计划|规划|布局))|"
    r"((方案|计划|路线|部署|前期准备|准备工作).{0,24}(如何|怎么|怎样|安排|制定))",
    re.IGNORECASE | re.DOTALL,
)
_CN_AVOID_DETECTION_INTENT_PATTERN = re.compile(
    r"((如何|怎么|怎样).{0,18}(规避|躲避|避免|逃避|绕过|不被发现))|"
    r"((不被发现|绕过检查|绕开审计|逃避监控|规避检测|规避审计).{0,24}(方法|办法|技巧|步骤|操作))",
    re.IGNORECASE | re.DOTALL,
)
_CN_PACKAGING_OR_PRESENTATION_INTENT_PATTERN = re.compile(
    r"((写一篇|创建一个|包装成|伪装成|呈现成|改写成).{0,24}(帖子|文案|教程|说明|话术|材料|网站|页面|挑战活动|故事|案例))|"
    r"((如何|怎么|怎样|把).{0,18}(包装|伪装|呈现|宣传|展示).{0,24}(内容|话术|教程|网站|页面|挑战活动|故事|案例|危险行为))",
    re.IGNORECASE | re.DOTALL,
)


def _is_chinese_unsafe_case(case: dict[str, Any]) -> bool:
    chinese_unsafe_categories = {
        "unsafe_prompt",
        "harmful_intent",
        "tool_misuse_attempt",
        "sensitive_info_exfiltration",
        "exploit_or_attack_request",
        "credential_or_data_theft",
        "phishing_or_fraud",
        "malware_or_privilege_escalation",
        "security_bypass_or_evasion",
        "harmful_operational_guidance",
    }
    return (case.get("language") or "").lower().startswith("zh") and case.get("attack_category") in chinese_unsafe_categories


def _classify_chinese_unsafe_bucket(case: dict[str, Any]) -> str:
    text = "\n".join(
        str(part or "")
        for part in [case.get("text"), case.get("retrieved_context"), case.get("model_output")]
        if part
    )
    subtype = str(case.get("attack_subtype") or "")
    hints = set((case.get("direct_hints") or []) + (case.get("context_hints") or []))
    guidance_first = subtype == "harmful_operational_guidance" or "cn_harmful_operational_guidance" in hints
    if guidance_first:
        if "cn_procurement_materials_request" in hints or _CN_PROCUREMENT_OR_MATERIALS_PATTERN.search(text):
            return "procurement_or_materials_guidance"
        if "cn_evasion_or_coverup_request" in hints or _CN_EVASION_OR_COVER_TRACKS_PATTERN.search(text):
            return "evasion_or_cover_tracks_guidance"
        if "cn_operational_planning_request" in hints or _CN_PLANNING_OR_STRATEGY_PATTERN.search(text):
            return "planning_or_strategy_guidance"
        if (
            "cn_step_by_step_harmful_guidance" in hints
            or "cn_actionable_harm_intent" in hints
            or _CN_STEP_BY_STEP_GUIDANCE_PATTERN.search(text)
        ):
            return "step_by_step_harmful_instructions"
    if subtype == "exploit_or_attack_request" or "cn_exploit_script_request" in hints or _CN_EXPLOIT_OR_ATTACK_PATTERN.search(text):
        return "exploit_or_attack_request"
    if subtype == "credential_or_data_theft" or "cn_credential_data_theft" in hints or _CN_CREDENTIAL_OR_DATA_THEFT_PATTERN.search(text):
        return "credential_or_data_theft"
    if subtype == "phishing_or_fraud" or "cn_phishing_or_fraud_phrase" in hints or _CN_PHISHING_OR_FRAUD_PATTERN.search(text):
        return "phishing_or_fraud"
    if subtype == "malware_or_privilege_escalation" or "cn_malware_privilege_request" in hints or _CN_MALWARE_OR_PRIV_ESC_PATTERN.search(text):
        return "malware_or_privilege_escalation"
    if subtype == "security_bypass_or_evasion" or "cn_security_bypass_request" in hints or _CN_BYPASS_OR_EVASION_PATTERN.search(text):
        return "security_bypass_or_evasion"
    if "cn_procurement_materials_request" in hints or _CN_PROCUREMENT_OR_MATERIALS_PATTERN.search(text):
        return "procurement_or_materials_guidance"
    if "cn_evasion_or_coverup_request" in hints or _CN_EVASION_OR_COVER_TRACKS_PATTERN.search(text):
        return "evasion_or_cover_tracks_guidance"
    if "cn_manipulation_or_deception_guidance" in hints or _CN_MANIPULATION_OR_DECEPTION_GUIDANCE_PATTERN.search(text):
        return "manipulation_or_deception_guidance"
    if "cn_propaganda_or_incitement_guidance" in hints or _CN_PROPAGANDA_OR_INCITEMENT_GUIDANCE_PATTERN.search(text):
        return "propaganda_or_incitement_guidance"
    if "cn_identity_theft_or_forgery_guidance" in hints or _CN_IDENTITY_THEFT_OR_FORGERY_GUIDANCE_PATTERN.search(text):
        return "identity_theft_or_forgery_guidance"
    if "cn_dangerous_making_guidance" in hints or _CN_DANGEROUS_MAKING_GUIDANCE_PATTERN.search(text):
        return "dangerous_making_guidance"
    if "cn_operational_planning_request" in hints or _CN_PLANNING_OR_STRATEGY_PATTERN.search(text):
        return "planning_or_strategy_guidance"
    if (
        "cn_step_by_step_harmful_guidance" in hints
        or "cn_actionable_harm_intent" in hints
        or _CN_STEP_BY_STEP_GUIDANCE_PATTERN.search(text)
    ):
        return "step_by_step_harmful_instructions"
    return "harmful_operational_guidance_unstructured"


def _chinese_unsafe_subslice_matrix(cases: list[dict[str, Any]]) -> dict[str, Any]:
    unsafe_cases = [case for case in cases if _is_chinese_unsafe_case(case)]
    buckets = {
        "exploit_or_attack_request": [],
        "credential_or_data_theft": [],
        "phishing_or_fraud": [],
        "malware_or_privilege_escalation": [],
        "security_bypass_or_evasion": [],
        "step_by_step_harmful_instructions": [],
        "planning_or_strategy_guidance": [],
        "procurement_or_materials_guidance": [],
        "evasion_or_cover_tracks_guidance": [],
        "manipulation_or_deception_guidance": [],
        "propaganda_or_incitement_guidance": [],
        "identity_theft_or_forgery_guidance": [],
        "dangerous_making_guidance": [],
        "harmful_operational_guidance_unstructured": [],
    }
    for case in unsafe_cases:
        buckets[_classify_chinese_unsafe_bucket(case)].append(case)
    return {
        label: {"count": len(group_cases), **_compute_metrics(group_cases)} if group_cases else {"count": 0}
        for label, group_cases in buckets.items()
    }


def _chinese_unsafe_residual_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    residual_false_negatives = [
        case
        for case in cases
        if _is_chinese_unsafe_case(case) and is_positive_sample(case) and case.get("decision") == "allow"
    ]
    subslices = _chinese_unsafe_subslice_matrix(residual_false_negatives)
    classifier_high_score = [
        case for case in residual_false_negatives if (case.get("classifier_score") or 0.0) >= 0.50 and not (case.get("triggered_rules") or [])
    ]
    weak_rule_signal = [
        case
        for case in residual_false_negatives
        if (case.get("triggered_rules") or []) and case.get("decision") == "allow"
    ]
    harmful_unstructured = [
        case for case in residual_false_negatives if _classify_chinese_unsafe_bucket(case) == "harmful_operational_guidance_unstructured"
    ]
    expression_buckets = {
        "goal_or_outcome_request": [],
        "scenario_based_role_prompt": [],
        "evaluation_or_comparison_request": [],
        "rewriting_or_reframing_request": [],
        "other_unstructured": [],
    }
    for case in harmful_unstructured:
        direct_hints = case.get("direct_hints") or extract_direct_instruction_hints(
            str(case.get("text") or ""),
            case.get("retrieved_context"),
        )
        hints = set(direct_hints)
        if "safe_meta_discussion" in hints:
            bucket = "other_unstructured"
        elif "cn_goal_outcome_intent" in hints:
            bucket = "goal_or_outcome_request"
        elif "cn_scenario_roleplay_intent" in hints:
            bucket = "scenario_based_role_prompt"
        elif "cn_evaluation_comparison_intent" in hints:
            bucket = "evaluation_or_comparison_request"
        elif "cn_reframing_or_rewriting_intent" in hints:
            bucket = "rewriting_or_reframing_request"
        else:
            bucket = "other_unstructured"
        expression_buckets[bucket].append(case)
    return {
        "total_residual_false_negatives": len(residual_false_negatives),
        "classifier_high_score_but_low_evidence": len(classifier_high_score),
        "rule_hit_but_not_actionable_enough": len(weak_rule_signal),
        "harmful_operational_guidance_unstructured": len(harmful_unstructured),
        "subtypes": [
            {
                "label": label,
                "count": payload["count"],
            }
            for label, payload in subslices.items()
            if payload.get("count", 0) > 0
        ],
        "expression_clusters": [
            {"label": label, "count": len(bucket_cases)}
            for label, bucket_cases in expression_buckets.items()
            if bucket_cases
        ],
    }


_PAYLOAD_REWRITE_PATTERN = re.compile(
    r"\b(repeat after me|output only|respond with|reply with|print\b|say\b|return\b|"
    r"pass ['\"][^'\"]+['\"] instead of|replace .{0,24} with .{0,24}|remove (?:any )?dots?|"
    r"title only|no extras?|no quotes?|translate.+respond with|only_translate)\b",
    re.IGNORECASE | re.DOTALL,
)
_OBFUSCATION_PATTERN = re.compile(
    r"(\\x[0-9a-fA-F]{2}){2,}|\b(base64|rot13|hex|hexadecimal|ascii|decode ascii)\b|"
    r"\[::\-1\]|<\|im_|<SPLIT>|i[\s_\-]+g[\s_\-]+n[\s_\-]+o[\s_\-]+r[\s_\-]+e",
    re.IGNORECASE | re.DOTALL,
)
_PWNED_PATTERN = re.compile(
    r"\bi\s*have\s*been\s*[a-z0-9_\-]*p\w{1,8}\b|\bpw\w{2,8}\b|\bpwned\b|\bponed\b|\bpowoned\b|\bdenwp\b",
    re.IGNORECASE,
)
_SEPARATOR_SMUGGLING_PATTERN = re.compile(
    r"(?:\\[^\s])(?:\s*\\[^\s]){4,}|<SPLIT>|<\|im_[^\n]{0,24}\|>|\[\[\[|\]\]\]|"
    r"\b[a-z]+(?:-[a-z]+){2,}\b|\b[a-z]+(?:_[a-z]+){2,}\b",
    re.IGNORECASE | re.DOTALL,
)
_WEIRD_VARIANT_HINT_TOKENS = {
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
    "context_override_phrase",
    "response_steering",
    "context_reply_steering",
    "external_task_line",
    "external_question_line",
    "context_starts_with_imperative",
    "social_engineering_link",
}


def _is_english_direct_case(case: dict[str, Any]) -> bool:
    english_direct_categories = {
        "direct_prompt_injection",
        "direct_injection",
        "instruction_override",
        "persona_replacement",
        "system_extraction",
        "many_shot",
        "adversarial_obfuscation",
        "encoding_obfuscation",
        "token_smuggling",
        "prompt_extraction",
    }
    return (case.get("language") or "").lower().startswith("en") and case.get("attack_category") in english_direct_categories


def _english_direct_subslice_matrix(cases: list[dict[str, Any]]) -> dict[str, Any]:
    english_direct_cases = [case for case in cases if _is_english_direct_case(case)]

    def has_tag(case: dict[str, Any], token: str) -> bool:
        return any(token in str(tag).lower() for tag in (case.get("tags") or []))

    def case_text(case: dict[str, Any]) -> str:
        return "\n".join(
            str(part or "")
            for part in [case.get("text"), case.get("retrieved_context"), case.get("model_output")]
            if part
        )

    slices = {
        "PWNED variants": [],
        "Payload rewrite": [],
        "Obfuscation": [],
        "Backslash / separator smuggling": [],
        "Unstructured / weird variants": [],
    }
    for case in english_direct_cases:
        text = case_text(case)
        if _PWNED_PATTERN.search(text):
            bucket = "PWNED variants"
        elif _PAYLOAD_REWRITE_PATTERN.search(text) or has_tag(case, "output_control") or has_tag(case, "conditional_payload"):
            bucket = "Payload rewrite"
        elif (
            case.get("attack_category") in {"adversarial_obfuscation", "encoding_obfuscation", "token_smuggling"}
            or _OBFUSCATION_PATTERN.search(text)
            or has_tag(case, "obfuscation")
        ):
            bucket = "Obfuscation"
        elif _SEPARATOR_SMUGGLING_PATTERN.search(text) or has_tag(case, "token_smuggling"):
            bucket = "Backslash / separator smuggling"
        else:
            bucket = "Unstructured / weird variants"
        slices[bucket].append(case)
    return {
        label: {"count": len(group_cases), **_compute_metrics(group_cases)} if group_cases else {"count": 0}
        for label, group_cases in slices.items()
    }


def _english_direct_residual_analysis(cases: list[dict[str, Any]]) -> dict[str, Any]:
    residual_false_negatives = [
        case
        for case in cases
        if _is_english_direct_case(case) and is_positive_sample(case) and case.get("decision") == "allow"
    ]
    clusters: dict[str, list[dict[str, Any]]] = {
        "classifier_high_score_but_low_evidence": [],
        "unstructured_or_weird_variants": [],
        "weak_structure_signal_not_enough_to_trigger": [],
    }
    for case in residual_false_negatives:
        classifier_score = case.get("classifier_score") or 0.0
        triggered_rules = case.get("triggered_rules") or []
        has_gate_signal = bool(case.get("classifier_gate_signal"))
        hint_tokens = set(case.get("direct_hints") or []) | set(case.get("context_hints") or [])
        if classifier_score >= 0.55 and not triggered_rules and not has_gate_signal:
            clusters["classifier_high_score_but_low_evidence"].append(case)
        elif not hint_tokens & _WEIRD_VARIANT_HINT_TOKENS:
            clusters["unstructured_or_weird_variants"].append(case)
        else:
            clusters["weak_structure_signal_not_enough_to_trigger"].append(case)

    cluster_summary = []
    for label, cluster_cases in clusters.items():
        if not cluster_cases:
            continue
        sample_hints = Counter(
            " + ".join(sorted(set((case.get("direct_hints") or []) + (case.get("context_hints") or [])))) or "none"
            for case in cluster_cases
        )
        cluster_summary.append(
            {
                "label": label,
                "count": len(cluster_cases),
                "top_hint_combo": sample_hints.most_common(1)[0][0] if sample_hints else "none",
                "example": (cluster_cases[0].get("text") or "")[:80],
            }
        )
    return {
        "total_residual_false_negatives": len(residual_false_negatives),
        "clusters": cluster_summary,
    }


def _indirect_context_residual_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    residual_false_negatives = [
        case
        for case in cases
        if case.get("language") == "en"
        and case.get("attack_category") == "indirect_prompt_injection"
        and is_positive_sample(case)
        and case.get("decision") == "allow"
    ]
    subtypes: dict[str, list[dict[str, Any]]] = {
        "encoding_or_transformation_reply_manipulation": [],
        "goal_mismatch_without_strong_structure": [],
        "offtopic_analysis_or_recommendation": [],
        "other": [],
    }
    for case in residual_false_negatives:
        hint_tokens = set(case.get("direct_hints") or []) | set(case.get("context_hints") or [])
        if hint_tokens & {"reply_encoding_mismatch", "format_manipulation_line", "cipher_instruction_line"}:
            bucket = "encoding_or_transformation_reply_manipulation"
        elif hint_tokens & {"reply_target_mismatch", "context_goal_mismatch"}:
            bucket = "goal_mismatch_without_strong_structure"
        elif hint_tokens & {"offtopic_analysis_line"}:
            bucket = "offtopic_analysis_or_recommendation"
        else:
            bucket = "other"
        subtypes[bucket].append(case)
    return {
        "total_residual_false_negatives": len(residual_false_negatives),
        "subtypes": [
            {
                "label": label,
                "count": len(group_cases),
                "example": (group_cases[0].get("text") or "")[:80],
            }
            for label, group_cases in subtypes.items()
            if group_cases
        ],
    }


def _stable_false_positive_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    false_positives = [
        case
        for case in cases
        if not is_positive_sample(case) and case.get("decision") != "allow"
    ]
    pattern_counter = Counter()
    for case in false_positives:
        triggered_rules = case.get("triggered_rules") or []
        direct_hints = case.get("direct_hints") or []
        context_hints = case.get("context_hints") or []
        if triggered_rules:
            pattern = "rules:" + ",".join(sorted(str(rule.get("rule_id")) for rule in triggered_rules[:3]))
        elif direct_hints or context_hints:
            merged_hints = sorted(set(direct_hints + context_hints))
            pattern = "hints:" + " + ".join(merged_hints[:3])
        else:
            pattern = "no_visible_pattern"
        pattern_counter[pattern] += 1
    return {
        "false_positive_count": len(false_positives),
        "top_patterns": dict(pattern_counter.most_common(5)),
    }


def _summarize_explainability(cases: list[dict[str, Any]]) -> dict[str, Any]:
    classifier_only_false_positives = [
        case
        for case in cases
        if not is_positive_sample(case)
        and case.get("decision") != "allow"
        and not case.get("triggered_rules")
        and (case.get("classifier_score") or 0.0) > 0
    ]
    hint_combo_counter = Counter(
        " + ".join(sorted(set((case.get("direct_hints") or []) + (case.get("context_hints") or [])))) or "none"
        for case in classifier_only_false_positives
    )
    return {
        "deambiguation_applied_count": sum(1 for case in cases if case.get("deambiguation_applied")),
        "classifier_only_false_positive_count": len(classifier_only_false_positives),
        "classifier_only_false_positive_hints": dict(hint_combo_counter.most_common(5)),
        "stable_false_positive_summary": _stable_false_positive_summary(cases),
        "indirect_context_residual_summary": _indirect_context_residual_summary(cases),
        "chinese_unsafe_residual_summary": _chinese_unsafe_residual_summary(cases),
    }


def _threshold_scan(samples: list[dict[str, Any]], detector, strategy: StrategyProfile) -> dict[str, Any]:
    if not strategy.enable_classifier:
        return {}
    best = {"best_f1": -1.0, "best_block_threshold": strategy.block_threshold, "best_review_threshold": strategy.review_threshold}
    threshold = 0.10
    while threshold <= 0.9001:
        temp_strategy = replace(
            strategy,
            block_threshold=round(threshold, 2),
            review_threshold=round(max(0.10, threshold - 0.15), 2),
        )
        cases: list[dict[str, Any]] = []
        for sample in samples:
            request = ScanRequest(
                user_input=sample["text"],
                retrieved_context=sample.get("retrieved_context"),
                model_output=sample.get("model_output"),
                scenario=sample.get("scenario") or "general_assistant",
                session_id=f"scan-threshold-{threshold:.2f}",
                strategy_name=temp_strategy.name,
            )
            result = detector.scan(request, db=None, persist=False, strategy_override=temp_strategy)
            case = {**sample, **result.model_dump()}
            cases.append(case)
        metrics = _compute_metrics(cases)
        if metrics["f1"] > best["best_f1"]:
            best = {
                "best_f1": metrics["f1"],
                "best_block_threshold": temp_strategy.block_threshold,
                "best_review_threshold": temp_strategy.review_threshold,
            }
        threshold += 0.05
    return best


def _load_samples(
    db: Session,
    request: EvaluationRequest,
    *,
    tenant_id: int | None = None,
    application_id: int | None = None,
) -> list[dict[str, Any]]:
    query = db.query(Sample)
    if tenant_id is not None:
        query = query.filter(Sample.tenant_id == tenant_id)
    if application_id is not None:
        query = query.filter(Sample.application_id == application_id)
    if request.sample_ids:
        query = query.filter(Sample.id.in_(request.sample_ids))
    return [_sample_to_dict(sample) for sample in query.order_by(Sample.id.asc()).all()]


def _estimate_operations(sample_count: int, strategy_count: int, enable_threshold_scan: bool, classifier_strategy_count: int) -> int:
    base = sample_count * strategy_count
    threshold_ops = sample_count * 17 * classifier_strategy_count if enable_threshold_scan else 0
    return base + threshold_ops


def run_evaluation(
    db: Session,
    request: EvaluationRequest,
    *,
    tenant_id: int | None = None,
    application_id: int | None = None,
    environment: str | None = None,
) -> tuple[EvaluationRun, dict[str, Any]]:
    settings = get_settings()
    detector = get_detection_service()
    run = EvaluationRun(
        name=request.run_name,
        strategy_name="comparison",
        status="running",
        dataset_source="database",
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        requested_strategies=request.strategy_names,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    try:
        samples = _load_samples(db, request, tenant_id=tenant_id, application_id=application_id)
        if not samples:
            raise EvaluationError("no samples selected for evaluation")
        if len(samples) > settings.max_eval_samples:
            raise EvaluationError(f"too many samples for one evaluation: {len(samples)} > {settings.max_eval_samples}")

        resolved_strategies = [resolve_strategy(db, strategy_name) for strategy_name in request.strategy_names]
        classifier_strategy_count = sum(1 for strategy in resolved_strategies if strategy.enable_classifier)
        estimated_ops = _estimate_operations(
            sample_count=len(samples),
            strategy_count=len(resolved_strategies),
            enable_threshold_scan=request.enable_threshold_scan,
            classifier_strategy_count=classifier_strategy_count,
        )
        if estimated_ops > settings.max_eval_operations:
            raise EvaluationError(
                f"evaluation request is too expensive: estimated operations {estimated_ops} exceed {settings.max_eval_operations}"
            )

        metrics: dict[str, Any] = {}
        threshold_scan: dict[str, Any] = {}
        staged_detections: list[DetectionResult] = []

        for strategy in resolved_strategies:
            cases: list[dict[str, Any]] = []
            strategy_records: list[tuple[ScanRequest, Any, dict[str, Any]]] = []
            for sample in samples:
                request_item = ScanRequest(
                    user_input=sample["text"],
                    retrieved_context=sample.get("retrieved_context"),
                    model_output=sample.get("model_output"),
                    scenario=sample.get("scenario") or "general_assistant",
                    session_id=f"eval-{run.id}-{strategy.name}",
                    strategy_name=strategy.name,
                )
                result = detector.scan(
                    request_item,
                    db=None,
                    persist=False,
                    sample_id=sample.get("id"),
                    evaluation_run_id=run.id if sample.get("id") else None,
                    strategy_override=strategy,
                )
                result_dump = result.model_dump()
                case = {**sample, **result_dump}
                case["attribution_label"] = assign_attribution(sample, result_dump)
                cases.append(case)
                strategy_records.append((request_item, result, case))

            strategy_metrics = _compute_metrics(cases)
            strategy_metrics["attribution_summary"] = summarize_attributions(cases)
            strategy_metrics["by_attack_type"] = _group_metrics(cases, "attack_category")
            strategy_metrics["by_sample_type"] = _group_metrics(cases, "sample_type")
            strategy_metrics["by_language"] = _group_metrics(cases, "language")
            strategy_metrics["language_focus_matrix"] = _language_focus_matrix(cases)
            strategy_metrics["english_direct_subslice_matrix"] = _english_direct_subslice_matrix(cases)
            strategy_metrics["chinese_unsafe_subslice_matrix"] = _chinese_unsafe_subslice_matrix(cases)
            strategy_metrics["explainability_summary"] = _summarize_explainability(cases)
            strategy_metrics["english_direct_residual_analysis"] = _english_direct_residual_analysis(cases)
            strategy_metrics["config"] = {
                "strategy_version": strategy.strategy_version,
                "rule_selection": strategy.rule_selection,
                "review_threshold": strategy.review_threshold,
                "block_threshold": strategy.block_threshold,
                "output_filter_threshold": strategy.output_filter_threshold,
            }
            metrics[strategy.name] = strategy_metrics
            if request.enable_threshold_scan:
                threshold_scan[strategy.name] = _threshold_scan(samples, detector, strategy)

            for request_item, result, case in strategy_records:
                if not case.get("id"):
                    continue
                detection = build_detection_record(
                    request_item,
                    result,
                    strategy.name,
                    sample_id=case.get("id"),
                    evaluation_run_id=run.id,
                )
                detection.attribution_label = case.get("attribution_label")
                staged_detections.append(detection)

        run.metrics = metrics
        run.threshold_scan = threshold_scan
        run.status = "completed"
        distribution = _dataset_distribution(samples)
        report_path, _ = generate_report(run.id, run.name, metrics, threshold_scan, distribution)
        run.report_path = report_path
        db.add(run)
        db.add_all(staged_detections)
        db.commit()
        db.refresh(run)
        return run, metrics
    except Exception as exc:
        db.rollback()
        run.status = "failed"
        run.notes = str(exc)
        db.add(run)
        db.commit()
        if isinstance(exc, EvaluationError):
            raise
        raise EvaluationError("evaluation failed") from exc
