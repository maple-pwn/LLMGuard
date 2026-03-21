from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from core.config import get_settings
from models.entities import DetectionResult, EvaluationRun, Rule, Sample


def _is_positive_sample(sample: Sample | None) -> bool:
    if sample is None:
        return False
    return sample.sample_type != "benign" or sample.expected_result != "allow"


def analyze_rule_effectiveness(
    db: Session,
    run_id: int | None = None,
    write_report: bool = True,
) -> tuple[list[dict[str, Any]], str]:
    settings = get_settings()
    run = None
    if run_id is not None:
        run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).one_or_none()
    if run is None:
        run = (
            db.query(EvaluationRun)
            .filter(EvaluationRun.status == "completed")
            .order_by(EvaluationRun.id.desc())
            .first()
        )
    detections_query = db.query(DetectionResult)
    if run is not None:
        detections_query = detections_query.filter(DetectionResult.evaluation_run_id == run.id)
    detections = detections_query.all()
    samples = {sample.id: sample for sample in db.query(Sample).all()}
    rules = db.query(Rule).order_by(Rule.rule_id.asc()).all()

    hit_sample_types: dict[str, Counter[str]] = defaultdict(Counter)
    hit_attack_types: dict[str, Counter[str]] = defaultdict(Counter)
    hit_count = Counter()
    block_contrib = Counter()
    review_contrib = Counter()
    false_positive_count = Counter()
    missed_potential = Counter()
    typical_hits: dict[str, list[str]] = defaultdict(list)

    for detection in detections:
        sample = samples.get(detection.sample_id)
        rule_ids = [item.get("rule_id") for item in (detection.triggered_rules or []) if item.get("rule_id")]
        unique_rule_ids = set(rule_ids)
        for rule_id in unique_rule_ids:
            hit_count[rule_id] += 1
            if sample is not None:
                hit_sample_types[rule_id][sample.sample_type] += 1
                hit_attack_types[rule_id][sample.attack_category or "benign"] += 1
                if len(typical_hits[rule_id]) < 3:
                    typical_hits[rule_id].append(sample.text[:80])
            if detection.decision == "block":
                block_contrib[rule_id] += 1
            elif detection.decision == "review":
                review_contrib[rule_id] += 1
            if sample is not None and not _is_positive_sample(sample) and detection.decision != "allow":
                false_positive_count[rule_id] += 1

        if sample is not None and _is_positive_sample(sample) and detection.decision == "allow":
            for rule in rules:
                if rule.category == (sample.attack_category or ""):
                    missed_potential[rule.rule_id] += 1

    rows: list[dict[str, Any]] = []
    for rule in rules:
        rows.append(
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "rule_version": rule.rule_version,
                "category": rule.category,
                "hit_count": hit_count[rule.rule_id],
                "hit_sample_type_distribution": dict(hit_sample_types[rule.rule_id]),
                "hit_attack_distribution": dict(hit_attack_types[rule.rule_id]),
                "block_contribution": block_contrib[rule.rule_id],
                "review_contribution": review_contrib[rule.rule_id],
                "false_positive_count": false_positive_count[rule.rule_id],
                "missed_opportunity_count": missed_potential[rule.rule_id],
                "typical_hits": typical_hits[rule.rule_id],
            }
        )

    if not write_report:
        return rows, ""
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    report_path = settings.report_dir / f"rule_effectiveness_{timestamp}.md"
    lines = [
        "# 规则运营分析报告\n\n",
        "| rule_id | version | hits | block | review | fp | missed potential |\n",
        "| --- | --- | --- | --- | --- | --- | --- |\n",
    ]
    for row in rows:
        lines.append(
            f"| {row['rule_id']} | {row['rule_version']} | {row['hit_count']} | {row['block_contribution']} | {row['review_contribution']} | {row['false_positive_count']} | {row['missed_opportunity_count']} |\n"
        )
    lines.append("\n## 典型命中样本\n")
    for row in rows[:10]:
        lines.append(f"\n### {row['rule_id']} - {row['name']}\n")
        for item in row["typical_hits"]:
            lines.append(f"- {item}\n")
    Path(report_path).write_text("".join(lines), encoding="utf-8")
    return rows, str(report_path)
