from __future__ import annotations

from collections import Counter
from dataclasses import replace
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
    }


def _group_metrics(cases: list[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        group_key = str(case.get(key) or "unknown")
        groups.setdefault(group_key, []).append(case)
    return {group_key: _compute_metrics(group_cases) for group_key, group_cases in groups.items()}


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
