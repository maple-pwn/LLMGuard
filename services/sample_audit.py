from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from core.config import get_settings
from models.entities import Sample


@dataclass
class AuditFinding:
    sample_id: int
    finding_type: str
    detail: str


def collect_sample_audit_findings(samples: list[Sample], similarity_threshold: float = 0.88) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    grouped: dict[tuple[str, str | None], list[Sample]] = defaultdict(list)
    for sample in samples:
        grouped[(sample.text.strip(), sample.scenario)].append(sample)

    for (_, _), bucket in grouped.items():
        if len(bucket) < 2:
            continue
        group_id = f"dup-{bucket[0].id}"
        for sample in bucket:
            findings.append(AuditFinding(sample.id, "duplicate", f"与样本 {bucket[0].id} 文本重复，分组 {group_id}"))

    for index, left in enumerate(samples):
        for right in samples[index + 1 :]:
            if left.id == right.id or left.text == right.text:
                continue
            score = SequenceMatcher(None, left.text, right.text).ratio()
            if score >= similarity_threshold:
                findings.append(AuditFinding(left.id, "high_similarity", f"与样本 {right.id} 相似度 {score:.2f}"))
                findings.append(AuditFinding(right.id, "high_similarity", f"与样本 {left.id} 相似度 {score:.2f}"))

    for sample in samples:
        if sample.sample_type != "benign" and not sample.attack_category:
            findings.append(AuditFinding(sample.id, "missing_label", "攻击或对抗样本缺少 attack_category"))
        if not sample.expected_result:
            findings.append(AuditFinding(sample.id, "missing_label", "样本缺少 expected_result"))
        if sample.sample_type == "benign" and sample.expected_result != "allow":
            findings.append(AuditFinding(sample.id, "label_conflict", "白样本 expected_result 不应为非 allow"))
        if sample.sample_type != "benign" and sample.expected_result == "allow":
            findings.append(AuditFinding(sample.id, "label_conflict", "攻击/对抗样本 expected_result 不应为 allow"))
        if (sample.label_confidence is not None and sample.label_confidence < 0.65) or sample.expected_result == "review":
            findings.append(AuditFinding(sample.id, "boundary", "低置信度或复核型样本，建议人工复核"))
        if sample.tags and any(tag in {"迷惑性白样本", "边界样本", "混合命中"} for tag in sample.tags):
            findings.append(AuditFinding(sample.id, "boundary", "标签指示其为边界或混合样本"))
    return findings


def apply_sample_audit(db: Session, findings: list[AuditFinding], samples: list[Sample] | None = None) -> dict[str, int]:
    finding_map: dict[int, list[AuditFinding]] = defaultdict(list)
    for finding in findings:
        finding_map[finding.sample_id].append(finding)

    updated = 0
    duplicate_groups: dict[int, str] = {}
    scoped_samples = samples if samples is not None else db.query(Sample).order_by(Sample.id.asc()).all()
    for sample in scoped_samples:
        sample_findings = finding_map.get(sample.id, [])
        if not sample_findings:
            continue
        updated += 1
        sample.needs_review = True
        sample.boundary_sample_flag = any(f.finding_type == "boundary" for f in sample_findings) or sample.boundary_sample_flag
        duplicate = next((f for f in sample_findings if f.finding_type == "duplicate"), None)
        if duplicate:
            group_id = duplicate.detail.split("分组 ")[-1]
            duplicate_groups[sample.id] = group_id
            sample.duplicate_group_id = group_id
        sample.review_comment = " | ".join(f"{item.finding_type}:{item.detail}" for item in sample_findings[:5])
    db.commit()
    counts = Counter(f.finding_type for f in findings)
    counts["updated_samples"] = updated
    return dict(counts)


def sample_audit_tips(sample: Sample) -> list[str]:
    tips: list[str] = []
    if sample.needs_review:
        tips.append("样本已进入复核队列")
    if sample.boundary_sample_flag:
        tips.append("样本被标记为边界样本")
    if sample.duplicate_group_id:
        tips.append(f"重复分组：{sample.duplicate_group_id}")
    if sample.review_comment:
        tips.append(sample.review_comment)
    if sample.label_confidence is not None and sample.label_confidence < 0.65:
        tips.append("标签置信度偏低")
    return tips


def generate_sample_audit_report(findings: list[AuditFinding]) -> tuple[str, str]:
    settings = get_settings()
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = settings.report_dir / f"sample_audit_{timestamp}.md"
    grouped: dict[str, list[AuditFinding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.finding_type].append(finding)

    sections = []
    for finding_type in ["duplicate", "high_similarity", "missing_label", "label_conflict", "boundary"]:
        rows = grouped.get(finding_type, [])
        sections.append(f"## {finding_type}\n")
        if not rows:
            sections.append("无\n")
            continue
        sections.append("| sample_id | detail |\n| --- | --- |\n")
        for row in rows[:80]:
            sections.append(f"| {row.sample_id} | {row.detail} |\n")

    content = "# 样本质量审计报告\n\n" + "".join(sections)
    Path(path).write_text(content, encoding="utf-8")
    return str(path), content


def audit_samples(
    db: Session,
    *,
    tenant_id: int | None = None,
    application_id: int | None = None,
) -> tuple[dict[str, int], str]:
    settings = get_settings()
    query = db.query(Sample)
    if tenant_id is not None:
        query = query.filter(Sample.tenant_id == tenant_id)
    if application_id is not None:
        query = query.filter(Sample.application_id == application_id)
    samples = query.order_by(Sample.id.asc()).all()
    sample_count = len(samples)
    if sample_count > settings.max_sample_audit_samples:
        raise ValueError(f"too many samples for audit: {sample_count} > {settings.max_sample_audit_samples}")
    pair_count = sample_count * (sample_count - 1) // 2
    if pair_count > settings.max_sample_audit_pairs:
        raise ValueError(f"audit request is too expensive: estimated pairs {pair_count} exceed {settings.max_sample_audit_pairs}")
    findings = collect_sample_audit_findings(samples)
    summary = apply_sample_audit(db, findings, samples=samples)
    report_path, _ = generate_sample_audit_report(findings)
    return summary, report_path
