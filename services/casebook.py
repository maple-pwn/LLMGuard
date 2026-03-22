from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from core.config import get_settings
from models.entities import CaseRecord, DetectionResult, EvaluationRun, Sample


def build_casebook(
    db: Session,
    run_id: int | None = None,
    owner: str = "security_ops",
    tenant_id: int | None = None,
    application_id: int | None = None,
) -> tuple[list[CaseRecord], str]:
    run = None
    if run_id is not None:
        run = db.query(EvaluationRun).filter(EvaluationRun.id == run_id).one_or_none()
    if run is None:
        query = db.query(EvaluationRun).filter(EvaluationRun.status == "completed")
        if tenant_id is not None:
            query = query.filter(EvaluationRun.tenant_id == tenant_id)
        if application_id is not None:
            query = query.filter(EvaluationRun.application_id == application_id)
        run = query.order_by(EvaluationRun.id.desc()).first()
    if run is None:
        raise ValueError("no completed evaluation run available")

    detections = db.query(DetectionResult).filter(DetectionResult.evaluation_run_id == run.id).all()
    samples = {sample.id: sample for sample in db.query(Sample).all()}
    created_cases: list[CaseRecord] = []

    for detection in detections:
        sample = samples.get(detection.sample_id)
        if sample is None:
            continue
        expected_positive = sample.sample_type != "benign" or sample.expected_result != "allow"
        predicted_positive = detection.decision != "allow"
        if predicted_positive and not expected_positive:
            case_type = "false_positive"
        elif (not predicted_positive) and expected_positive:
            case_type = "false_negative"
        else:
            continue
        existing = (
            db.query(CaseRecord)
            .filter(
                CaseRecord.sample_id == sample.id,
                CaseRecord.evaluation_run_id == run.id,
                CaseRecord.case_type == case_type,
            )
            .one_or_none()
        )
        if existing is not None:
            created_cases.append(existing)
            continue
        root_cause = detection.attribution_label or ("规则范围过宽" if case_type == "false_positive" else "规则覆盖不足")
        analysis = (
            f"样本 {sample.id} 在评测运行 {run.id} 中被识别为 {case_type}。"
            f"命中规则数 {len(detection.triggered_rules or [])}，风险分数 {detection.risk_score:.2f}。"
        )
        fix = (
            "补充白样本和收紧规则语义边界，必要时下调规则权重。"
            if case_type == "false_positive"
            else "补充同类攻击模板、增强规则覆盖并调整分类阈值。"
        )
        case = CaseRecord(
            sample_id=sample.id,
            evaluation_run_id=run.id,
            tenant_id=run.tenant_id or detection.tenant_id,
            application_id=run.application_id or detection.application_id,
            case_type=case_type,
            attack_category=sample.attack_category,
            root_cause=root_cause,
            triggered_rules=detection.triggered_rules or [],
            risk_score=detection.risk_score,
            expected_decision=sample.expected_result,
            actual_decision=detection.decision,
            analysis_text=analysis,
            fix_suggestion=fix,
            owner=owner,
            status="open",
        )
        db.add(case)
        db.flush()
        case.doc_path = _write_case_doc(case, sample)
        created_cases.append(case)
    db.commit()
    report_path = _write_casebook_index(created_cases)
    return created_cases, report_path


def _write_case_doc(case: CaseRecord, sample: Sample) -> str:
    settings = get_settings()
    path = settings.report_dir.parent / "cases" / f"case_{case.id}.md"
    content = f"""# 案例 {case.id}

## 基本信息

- case_type: `{case.case_type}`
- attack_category: `{case.attack_category or '-'}`
- expected: `{case.expected_decision}`
- actual: `{case.actual_decision}`
- root_cause: `{case.root_cause}`

## 样本文本

{sample.text}

## 命中规则

{case.triggered_rules}

## 分析

{case.analysis_text}

## 修复建议

{case.fix_suggestion}
"""
    Path(path).write_text(content, encoding="utf-8")
    return str(path)


def _write_casebook_index(cases: list[CaseRecord]) -> str:
    settings = get_settings()
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = settings.report_dir.parent / "cases" / f"casebook_{timestamp}.md"
    lines = ["# 误报漏报案例集\n\n", "| case_id | type | root_cause | status |\n", "| --- | --- | --- | --- |\n"]
    for case in cases:
        lines.append(f"| {case.id} | {case.case_type} | {case.root_cause} | {case.status} |\n")
    Path(path).write_text("".join(lines), encoding="utf-8")
    return str(path)


def list_cases(
    db: Session,
    case_type: str | None = None,
    attack_category: str | None = None,
    root_cause: str | None = None,
    status: str | None = None,
) -> list[CaseRecord]:
    query = db.query(CaseRecord)
    if case_type:
        query = query.filter(CaseRecord.case_type == case_type)
    if attack_category:
        query = query.filter(CaseRecord.attack_category == attack_category)
    if root_cause:
        query = query.filter(CaseRecord.root_cause == root_cause)
    if status:
        query = query.filter(CaseRecord.status == status)
    return query.order_by(CaseRecord.created_at.desc()).all()
