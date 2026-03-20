from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from core.bootstrap import bootstrap, seed_default_strategies
from core.database import SessionLocal
from models.entities import CaseRecord, DetectionResult, EvaluationRun, Rule, Sample, StrategyConfig
from models.schemas import EvaluationRequest, ScanRequest
from services.casebook import build_casebook, list_cases
from services.compare import compare_evaluation_runs
from services.detection import get_detection_service
from services.evaluation import run_evaluation
from services.ops_reporting import generate_postmortem, generate_weekly_report
from services.rule_analysis import analyze_rule_effectiveness
from services.sample_audit import audit_samples, sample_audit_tips


st.set_page_config(page_title="LLM Firewall Ops Console", layout="wide")
st.title("LLM Firewall 安全运营与评测平台")

db = SessionLocal()
bootstrap(db)
seed_default_strategies(db)


def _frame_from_samples(samples: list[Sample]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "id": sample.id,
                "sample_type": sample.sample_type,
                "attack_category": sample.attack_category or "benign",
                "scenario": sample.scenario,
                "expected_result": sample.expected_result,
                "needs_review": sample.needs_review,
                "boundary": sample.boundary_sample_flag,
                "confidence": sample.label_confidence,
                "text": sample.text,
            }
            for sample in samples
        ]
    )


def _read_text(path: str | None) -> str:
    if not path:
        return ""
    file_path = Path(path)
    if not file_path.exists():
        return ""
    return file_path.read_text(encoding="utf-8")


all_samples = db.query(Sample).all()
all_rules = db.query(Rule).all()
all_runs = db.query(EvaluationRun).order_by(EvaluationRun.id.desc()).all()
all_cases = db.query(CaseRecord).order_by(CaseRecord.created_at.desc()).all()
latest_run = next((run for run in all_runs if run.status == "completed"), None)
completed_run_ids = [run.id for run in all_runs if run.status == "completed"]

overview_tab, scan_tab, review_tab, rules_tab, cases_tab, compare_tab, sample_tab, reports_tab = st.tabs(
    ["项目概览", "单次检测", "样本复核", "规则运营分析", "案例中心", "策略对比", "单样本分析", "报告中心"]
)

with overview_tab:
    st.subheader("项目概览")
    attack_count = sum(1 for sample in all_samples if sample.sample_type != "benign")
    benign_count = sum(1 for sample in all_samples if sample.sample_type == "benign")
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("样本总数", len(all_samples))
    col2.metric("攻击/对抗样本", attack_count)
    col3.metric("白样本", benign_count)
    col4.metric("规则数", len(all_rules))
    col5.metric("案例数", len(all_cases))

    left, right = st.columns(2)
    sample_frame = _frame_from_samples(all_samples)
    if not sample_frame.empty:
        with left:
            st.caption("样本分布")
            st.bar_chart(sample_frame["sample_type"].value_counts())
            st.caption("攻击类型分布")
            st.bar_chart(sample_frame["attack_category"].value_counts().head(10))
        with right:
            if latest_run and latest_run.metrics:
                full_stack = latest_run.metrics.get("full_stack") or next(iter(latest_run.metrics.values()))
                issue_frame = pd.DataFrame(
                    {
                        "type": ["false_positive", "false_negative"],
                        "count": [
                            len(full_stack.get("typical_false_positives", [])),
                            len(full_stack.get("typical_false_negatives", [])),
                        ],
                    }
                )
                st.caption(f"最近一次评测摘要：Run {latest_run.id} - {latest_run.name}")
                st.json(full_stack.get("config", {}))
                st.bar_chart(issue_frame.set_index("type"))
            rule_rows, _ = analyze_rule_effectiveness(db, run_id=latest_run.id if latest_run else None, write_report=False)
            if rule_rows:
                st.caption("规则命中排行")
                st.dataframe(pd.DataFrame(rule_rows)[["rule_id", "name", "hit_count", "false_positive_count"]].head(10), use_container_width=True)

with scan_tab:
    st.subheader("检测网关演示")
    scenario = st.selectbox("场景", ["general_assistant", "knowledge_base_qa", "office_assistant", "code_assistant"])
    user_input = st.text_area("用户输入", height=120, value="帮我总结这份周报，并提炼行动项。")
    retrieved_context = st.text_area("检索上下文", height=120)
    model_output = st.text_area("模型输出", height=120)
    tenant_slug = st.text_input("tenant_slug", value="default")
    application_key = st.text_input("application_key", value="demo-office-assistant")
    environment = st.selectbox("environment", ["prod", "staging", "dev"], index=0)
    strategies = [strategy.name for strategy in db.query(StrategyConfig).order_by(StrategyConfig.name.asc()).all()]
    strategy_name = st.selectbox("策略", strategies, index=min(2, len(strategies) - 1))
    if st.button("执行扫描"):
        result = get_detection_service().scan(
            ScanRequest(
                user_input=user_input,
                retrieved_context=retrieved_context or None,
                model_output=model_output or None,
                scenario=scenario,
                session_id="streamlit-demo",
                strategy_name=strategy_name,
                tenant_slug=tenant_slug,
                application_key=application_key,
                environment=environment,
            ),
            db=db,
            persist=True,
        )
        st.json(result.model_dump())

with review_tab:
    st.subheader("样本复核队列")
    cols = st.columns(4)
    needs_review_filter = cols[0].selectbox("needs_review", ["all", "true", "false"], index=1)
    boundary_filter = cols[1].selectbox("boundary", ["all", "true", "false"], index=0)
    attack_filter = cols[2].selectbox("attack_type", ["all"] + sorted({sample.attack_category for sample in all_samples if sample.attack_category}))
    scenario_filter = cols[3].selectbox("scenario", ["all"] + sorted({sample.scenario for sample in all_samples if sample.scenario}))
    if st.button("运行样本审计"):
        try:
            summary, report_path = audit_samples(db)
        except ValueError as exc:
            st.error(str(exc))
        else:
            st.success(f"样本审计完成：{report_path}")
            st.json(summary)
    queue = db.query(Sample).order_by(Sample.created_at.desc()).all()
    filtered_queue = []
    for sample in queue:
        if needs_review_filter != "all" and sample.needs_review != (needs_review_filter == "true"):
            continue
        if boundary_filter != "all" and sample.boundary_sample_flag != (boundary_filter == "true"):
            continue
        if attack_filter != "all" and sample.attack_category != attack_filter:
            continue
        if scenario_filter != "all" and sample.scenario != scenario_filter:
            continue
        filtered_queue.append(sample)
    for sample in filtered_queue[:100]:
        with st.expander(f"#{sample.id} [{sample.sample_type}] {sample.text[:60]}"):
            st.write({"expected": sample.expected_result, "actual": sample.actual_result, "scenario": sample.scenario})
            st.write({"review_comment": sample.review_comment, "confidence": sample.label_confidence})
            st.write("审计提示：", sample_audit_tips(sample))
            if sample.retrieved_context:
                st.caption("retrieved_context")
                st.code(sample.retrieved_context)
            if sample.model_output:
                st.caption("model_output")
                st.code(sample.model_output)

with rules_tab:
    st.subheader("规则运营分析")
    if not completed_run_ids:
        st.info("暂无可用的 completed evaluation run")
    else:
        selected_run_id = st.selectbox("评测运行", completed_run_ids, index=0)
        if st.button("刷新规则分析"):
            rule_rows, report_path = analyze_rule_effectiveness(db, run_id=selected_run_id, write_report=True)
            st.success(f"规则运营报告：{report_path}")
            st.dataframe(pd.DataFrame(rule_rows), use_container_width=True)
        else:
            rule_rows, _ = analyze_rule_effectiveness(db, run_id=selected_run_id, write_report=False)
            st.dataframe(pd.DataFrame(rule_rows), use_container_width=True)

with cases_tab:
    st.subheader("误报漏报案例中心")
    case_cols = st.columns(4)
    case_type_filter = case_cols[0].selectbox("case_type", ["all", "false_positive", "false_negative"])
    attack_type_filter = case_cols[1].selectbox("attack_type", ["all"] + sorted({case.attack_category for case in all_cases if case.attack_category}))
    root_cause_filter = case_cols[2].selectbox("root_cause", ["all"] + sorted({case.root_cause for case in all_cases}))
    status_filter = case_cols[3].selectbox("status", ["all"] + sorted({case.status for case in all_cases}))
    if st.button("构建案例中心"):
        cases, report_path = build_casebook(db, run_id=latest_run.id if latest_run else None)
        st.success(f"案例文档已生成：{report_path}，新增/刷新 {len(cases)} 条案例")
    filtered_cases = list_cases(
        db,
        case_type=None if case_type_filter == "all" else case_type_filter,
        attack_category=None if attack_type_filter == "all" else attack_type_filter,
        root_cause=None if root_cause_filter == "all" else root_cause_filter,
        status=None if status_filter == "all" else status_filter,
    )
    for case in filtered_cases[:100]:
        sample = db.query(Sample).filter(Sample.id == case.sample_id).one_or_none()
        with st.expander(f"Case {case.id} [{case.case_type}] {case.root_cause}"):
            if sample:
                st.write(sample.text)
            st.write({"expected": case.expected_decision, "actual": case.actual_decision, "risk_score": case.risk_score})
            st.write("triggered_rules", case.triggered_rules)
            st.write("analysis", case.analysis_text)
            st.write("fix", case.fix_suggestion)
            if case.doc_path:
                st.code(_read_text(case.doc_path))

with compare_tab:
    st.subheader("策略对比")
    completed_runs = [run for run in all_runs if run.status == "completed"]
    selected_runs = st.multiselect(
        "选择 evaluation runs",
        options=[run.id for run in completed_runs],
        default=[run.id for run in completed_runs[:2]],
    )
    if selected_runs:
        compare_result = compare_evaluation_runs(db, selected_runs)
        st.caption("总体指标表")
        st.dataframe(pd.DataFrame(compare_result["overall"]), use_container_width=True)
        st.caption("按攻击类型聚合")
        st.json(compare_result["by_attack_type"])
        st.caption("按样本类型聚合")
        st.json(compare_result["by_sample_type"])
        st.caption("阈值扫描结果")
        st.json(compare_result["threshold_scan"])
    run_name = st.text_input("新评测名称", value="streamlit_phase2_eval")
    selected_strategies = st.multiselect(
        "选择策略配置",
        [strategy.name for strategy in db.query(StrategyConfig).order_by(StrategyConfig.name.asc()).all()],
        default=["rules_only", "rules_classifier", "full_stack"],
    )
    if st.button("执行新一轮评测"):
        run, metrics = run_evaluation(db, EvaluationRequest(run_name=run_name, strategy_names=selected_strategies))
        st.success(f"完成 run {run.id}")
        st.json(metrics)

with sample_tab:
    st.subheader("单样本分析")
    sample_id = st.number_input("输入 sample_id", min_value=1, step=1, value=1)
    sample = db.query(Sample).filter(Sample.id == sample_id).one_or_none()
    if sample is None:
        st.info("sample not found")
    else:
        st.write(
            {
                "sample_type": sample.sample_type,
                "attack_category": sample.attack_category,
                "expected_result": sample.expected_result,
                "actual_result": sample.actual_result,
                "needs_review": sample.needs_review,
                "boundary_sample_flag": sample.boundary_sample_flag,
                "review_comment": sample.review_comment,
            }
        )
        st.write(sample.text)
        st.caption("历史检测记录")
        detections = db.query(DetectionResult).filter(DetectionResult.sample_id == sample.id).order_by(DetectionResult.created_at.desc()).all()
        for detection in detections[:20]:
            st.write(
                {
                    "strategy": detection.strategy_name,
                    "decision": detection.decision,
                    "risk_type": detection.risk_type,
                    "risk_score": detection.risk_score,
                    "attribution": detection.attribution_label,
                    "created_at": str(detection.created_at),
                }
            )
            st.json({"triggered_rules": detection.triggered_rules, "reason": detection.reason})

with reports_tab:
    st.subheader("报告中心")
    report_cols = st.columns(3)
    weekly_title = report_cols[0].text_input("weekly title", value="weekly_report")
    postmortem_title = report_cols[1].text_input("postmortem title", value="evaluation_postmortem")
    if report_cols[2].button("生成周报"):
        st.success(generate_weekly_report(db, title=weekly_title))
    if st.button("生成复盘文档"):
        st.success(generate_postmortem(db, title=postmortem_title, run_id=latest_run.id if latest_run else None))

    report_paths = []
    for folder in ["reports", "weekly_reports", "cases", "postmortems"]:
        base = Path("docs") / folder
        report_paths.extend(sorted(base.glob("*.md"), reverse=True))
    for report_path in report_paths[:80]:
        with st.expander(str(report_path)):
            st.code(report_path.read_text(encoding="utf-8"))
