from __future__ import annotations

from services.attribution import assign_attribution
from services.evaluation import _compute_metrics


def test_compute_metrics_counts_confusion_matrix() -> None:
    cases = [
        {"sample_type": "attack", "expected_result": "block", "decision": "block", "latency_ms": 1.0},
        {"sample_type": "attack", "expected_result": "review", "decision": "allow", "latency_ms": 2.0},
        {"sample_type": "benign", "expected_result": "allow", "decision": "allow", "latency_ms": 1.5},
        {"sample_type": "benign", "expected_result": "allow", "decision": "review", "latency_ms": 1.2},
    ]
    metrics = _compute_metrics(cases)
    assert metrics["confusion_matrix"] == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}
    assert metrics["manual_review_rate"] == 0.25


def test_assign_attribution_for_false_positive_overlap() -> None:
    sample = {
        "sample_type": "benign",
        "expected_result": "allow",
        "tags": ["迷惑性白样本"],
    }
    result = {
        "decision": "block",
        "triggered_rules": [{"rule_id": "R002"}],
        "classifier_score": 0.3,
        "output_filter_score": 0.0,
    }
    assert assign_attribution(sample, result) == "白样本与攻击模板局部重叠"
