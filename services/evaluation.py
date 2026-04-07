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
        "Payload rewrite": [
            case
            for case in english_direct_cases
            if _PAYLOAD_REWRITE_PATTERN.search(case_text(case))
            or has_tag(case, "output_control")
            or has_tag(case, "conditional_payload")
        ],
        "Obfuscation": [
            case
            for case in english_direct_cases
            if case.get("attack_category") in {"adversarial_obfuscation", "encoding_obfuscation", "token_smuggling"}
            or _OBFUSCATION_PATTERN.search(case_text(case))
            or has_tag(case, "obfuscation")
        ],
        "PWNED variants": [
            case
            for case in english_direct_cases
            if _PWNED_PATTERN.search(case_text(case))
        ],
        "Backslash / separator smuggling": [
            case
            for case in english_direct_cases
            if _SEPARATOR_SMUGGLING_PATTERN.search(case_text(case))
            or has_tag(case, "token_smuggling")
        ],
    }
    return {
        label: {"count": len(group_cases), **_compute_metrics(group_cases)} if group_cases else {"count": 0}
        for label, group_cases in slices.items()
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
        " + ".join(case.get("direct_hints") or case.get("context_hints") or ["none"])
        for case in classifier_only_false_positives
    )
    return {
        "deambiguation_applied_count": sum(1 for case in cases if case.get("deambiguation_applied")),
        "classifier_only_false_positive_count": len(classifier_only_false_positives),
        "classifier_only_false_positive_hints": dict(hint_combo_counter.most_common(5)),
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
            strategy_metrics["explainability_summary"] = _summarize_explainability(cases)
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
