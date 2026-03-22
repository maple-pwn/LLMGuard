from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from models.entities import DetectionResult, EvaluationRun, Sample


def _positive(sample: Sample | None) -> bool:
    return bool(sample and (sample.sample_type != "benign" or sample.expected_result != "allow"))


def _metric_block(cases: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for case in cases:
        expected_positive = case["expected_positive"]
        predicted_positive = case["decision"] != "allow"
        if predicted_positive and expected_positive:
            tp += 1
        elif predicted_positive and not expected_positive:
            fp += 1
        elif (not predicted_positive) and expected_positive:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "count": len(cases)}


def compare_evaluation_runs(db: Session, run_ids: list[int]) -> dict[str, Any]:
    runs = db.query(EvaluationRun).filter(EvaluationRun.id.in_(run_ids)).order_by(EvaluationRun.id.asc()).all()
    samples = {sample.id: sample for sample in db.query(Sample).all()}
    output: dict[str, Any] = {"runs": [], "overall": [], "by_attack_type": {}, "by_sample_type": {}, "threshold_scan": {}}

    for run in runs:
        detections = db.query(DetectionResult).filter(DetectionResult.evaluation_run_id == run.id).all()
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for detection in detections:
            sample = samples.get(detection.sample_id)
            grouped[detection.strategy_name or "unknown"].append(
                {
                    "sample_id": detection.sample_id,
                    "sample_type": sample.sample_type if sample else "unknown",
                    "attack_category": sample.attack_category if sample else None,
                    "expected_positive": _positive(sample),
                    "decision": detection.decision,
                    "latency_ms": detection.latency_ms,
                    "risk_score": detection.risk_score,
                }
            )
        output["runs"].append({"run_id": run.id, "name": run.name, "strategies": list(grouped.keys())})
        output["threshold_scan"][run.id] = run.threshold_scan or {}

        for strategy_name, cases in grouped.items():
            label = f"run_{run.id}:{strategy_name}"
            overall = _metric_block(cases)
            output["overall"].append({"label": label, **overall})
            attack_grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
            sample_type_grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for case in cases:
                attack_grouped[case["attack_category"] or "benign"].append(case)
                sample_type_grouped[case["sample_type"]].append(case)
            output["by_attack_type"][label] = {key: _metric_block(value) for key, value in attack_grouped.items()}
            output["by_sample_type"][label] = {key: _metric_block(value) for key, value in sample_type_grouped.items()}
    return output
