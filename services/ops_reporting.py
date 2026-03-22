from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
import re

from sqlalchemy.orm import Session

from core.config import get_settings
from models.entities import CaseRecord, EvaluationRun, Rule, Sample


def _safe_report_title(title: str) -> str:
    candidate = title.strip()
    if not candidate:
        raise ValueError("title must not be empty")
    path_candidate = Path(candidate)
    if path_candidate.is_absolute() or len(path_candidate.parts) != 1 or any(part in {".", ".."} for part in path_candidate.parts):
        raise ValueError("title contains invalid path characters")
    if not re.fullmatch(r"[A-Za-z0-9_\-\u4e00-\u9fff]+", candidate):
        raise ValueError("title contains unsupported characters")
    return candidate


def _safe_report_path(folder: str, title: str) -> Path:
    settings = get_settings()
    base_dir = (settings.report_dir.parent / folder).resolve()
    safe_title = _safe_report_title(title)
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = (base_dir / f"{safe_title}_{timestamp}.md").resolve()
    try:
        path.relative_to(base_dir)
    except ValueError as exc:
        raise ValueError("invalid report output path") from exc
    return path


def generate_weekly_report(
    db: Session,
    title: str = "weekly_report",
    tenant_id: int | None = None,
    application_id: int | None = None,
) -> str:
    since = datetime.now(UTC) - timedelta(days=7)
    new_samples = db.query(Sample).filter(Sample.created_at >= since).all()
    case_query = db.query(CaseRecord).filter(CaseRecord.created_at >= since)
    if tenant_id is not None:
        case_query = case_query.filter(CaseRecord.tenant_id == tenant_id)
    if application_id is not None:
        case_query = case_query.filter(CaseRecord.application_id == application_id)
    cases = case_query.all()
    rules = db.query(Rule).filter(Rule.updated_at >= since).all()
    run_query = db.query(EvaluationRun).filter(EvaluationRun.status == "completed")
    if tenant_id is not None:
        run_query = run_query.filter(EvaluationRun.tenant_id == tenant_id)
    if application_id is not None:
        run_query = run_query.filter(EvaluationRun.application_id == application_id)
    latest_run = run_query.order_by(EvaluationRun.id.desc()).first()
    attack_distribution = Counter(sample.attack_category or "benign" for sample in new_samples)
    false_positive_roots = Counter(case.root_cause for case in cases if case.case_type == "false_positive")
    false_negative_roots = Counter(case.root_cause for case in cases if case.case_type == "false_negative")
    threshold_suggestion = latest_run.threshold_scan if latest_run else {}

    safe_title = _safe_report_title(title)
    path = _safe_report_path("weekly_reports", safe_title)
    content = f"""# 周报 - {title}

## 本周新增样本数

{len(new_samples)}

## 攻击类型分布变化

{dict(attack_distribution)}

## 误报主要问题

{dict(false_positive_roots)}

## 漏报主要问题

{dict(false_negative_roots)}

## 规则更新摘要

本周更新规则数：{len(rules)}

## 阈值调整建议

{threshold_suggestion}

## 下周工作计划

1. 补充边界样本与迷惑性白样本。
2. 对高误报规则进行语义收紧与权重微调。
3. 对重点攻击类型继续做阈值扫描和规则组合对比。
"""
    path.write_text(content, encoding="utf-8")
    return str(path)


def generate_postmortem(
    db: Session,
    title: str = "evaluation_postmortem",
    run_id: int | None = None,
    tenant_id: int | None = None,
    application_id: int | None = None,
) -> str:
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
    cases = db.query(CaseRecord).filter(CaseRecord.evaluation_run_id == run.id).all()
    safe_title = _safe_report_title(title)
    path = _safe_report_path("postmortems", safe_title)
    content = f"""# 复盘 - {title}

## 问题现象

评测运行 `{run.id}` 暴露出误报与漏报案例，需要从规则覆盖、阈值设置和样本治理三方面复盘。

## 影响范围

- 运行名称：`{run.name}`
- 案例数：`{len(cases)}`

## 根因分析

{[case.root_cause for case in cases[:10]]}

## 修复动作

1. 补充对应攻击类别样本。
2. 调整高误报规则的权重与场景约束。
3. 对分类器阈值做分场景细化。

## 后续跟踪项

1. 重新跑一轮对比评测。
2. 观察误报漏报案例是否下降。
3. 将修复经验沉淀进案例中心与周报。
"""
    path.write_text(content, encoding="utf-8")
    return str(path)
