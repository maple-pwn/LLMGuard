from __future__ import annotations

from pathlib import Path
from typing import Any

from core.config import get_settings


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "无\n"
    header_line = "| " + " | ".join(headers) + " |"
    divider = "| " + " | ".join(["---"] * len(headers)) + " |"
    body = "\n".join("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join([header_line, divider, body])


def generate_report(
    run_id: int,
    run_name: str,
    metrics: dict[str, Any],
    threshold_scan: dict[str, Any],
    sample_distribution: dict[str, Any],
) -> tuple[str, str]:
    settings = get_settings()
    report_path = settings.report_dir / f"run_{run_id}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    comparison_rows = []
    for strategy_name, payload in metrics.items():
        comparison_rows.append(
            [
                strategy_name,
                f"{payload['precision']:.3f}",
                f"{payload['recall']:.3f}",
                f"{payload['f1']:.3f}",
                f"{payload['fpr']:.3f}",
                f"{payload['fnr']:.3f}",
                f"{payload['manual_review_rate']:.3f}",
                f"{payload['avg_latency_ms']:.2f}",
            ]
        )

    focus_strategy_name = "context_hardened_v3" if "context_hardened_v3" in metrics else ("full_stack" if "full_stack" in metrics else next(iter(metrics)))
    focus_strategy = metrics[focus_strategy_name]
    attribution_rows = [
        [label, str(count)] for label, count in (focus_strategy.get("attribution_summary") or {}).items()
    ]
    fp_rows = [
        [case["sample_type"], case["decision"], case["attack_category"] or "-", case["text"][:40]]
        for case in focus_strategy.get("typical_false_positives", [])
    ]
    fn_rows = [
        [case["sample_type"], case["decision"], case["attack_category"] or "-", case["text"][:40]]
        for case in focus_strategy.get("typical_false_negatives", [])
    ]
    threshold_rows = []
    for strategy_name, payload in threshold_scan.items():
        if not payload:
            threshold_rows.append([strategy_name, "-", "-", "-"])
            continue
        threshold_rows.append(
            [
                strategy_name,
                f"{payload['best_block_threshold']:.2f}",
                f"{payload['best_review_threshold']:.2f}",
                f"{payload['best_f1']:.3f}",
            ]
        )

    language_rows = []
    for language, payload in (focus_strategy.get("by_language") or {}).items():
        language_rows.append(
            [
                language,
                f"{payload['precision']:.3f}",
                f"{payload['recall']:.3f}",
                f"{payload['f1']:.3f}",
                str(sum(payload["confusion_matrix"].values())),
            ]
        )

    focus_matrix_rows = []
    for label, payload in (focus_strategy.get("language_focus_matrix") or {}).items():
        if not payload or payload.get("count", 0) == 0:
            focus_matrix_rows.append([label, "0", "-", "-", "-"])
            continue
        focus_matrix_rows.append(
            [
                label,
                str(payload["count"]),
                f"{payload['precision']:.3f}",
                f"{payload['recall']:.3f}",
                f"{payload['f1']:.3f}",
            ]
        )

    english_direct_subslice_rows = []
    for label, payload in (focus_strategy.get("english_direct_subslice_matrix") or {}).items():
        if not payload or payload.get("count", 0) == 0:
            english_direct_subslice_rows.append([label, "0", "-", "-", "-"])
            continue
        english_direct_subslice_rows.append(
            [
                label,
                str(payload["count"]),
                f"{payload['precision']:.3f}",
                f"{payload['recall']:.3f}",
                f"{payload['f1']:.3f}",
            ]
        )

    chinese_unsafe_subslice_rows = []
    for label, payload in (focus_strategy.get("chinese_unsafe_subslice_matrix") or {}).items():
        if not payload or payload.get("count", 0) == 0:
            chinese_unsafe_subslice_rows.append([label, "0", "-", "-", "-"])
            continue
        chinese_unsafe_subslice_rows.append(
            [
                label,
                str(payload["count"]),
                f"{payload['precision']:.3f}",
                f"{payload['recall']:.3f}",
                f"{payload['f1']:.3f}",
            ]
        )

    explainability_summary = focus_strategy.get("explainability_summary") or {}
    explainability_rows = [
        ["办公编辑去歧义触发数", str(explainability_summary.get("deambiguation_applied_count", 0))],
        ["classifier-only 误报数", str(explainability_summary.get("classifier_only_false_positive_count", 0))],
    ]
    classifier_only_hint_rows = [
        [hint_combo, str(count)]
        for hint_combo, count in (explainability_summary.get("classifier_only_false_positive_hints") or {}).items()
    ]
    stable_false_positive_rows = [
        [pattern, str(count)]
        for pattern, count in ((explainability_summary.get("stable_false_positive_summary") or {}).get("top_patterns") or {}).items()
    ]
    indirect_residual_summary = explainability_summary.get("indirect_context_residual_summary") or {}
    indirect_residual_rows = [
        [
            subtype["label"],
            str(subtype["count"]),
            subtype["example"],
        ]
        for subtype in indirect_residual_summary.get("subtypes", [])
    ]
    residual_analysis = focus_strategy.get("english_direct_residual_analysis") or {}
    residual_rows = [
        [
            cluster["label"],
            str(cluster["count"]),
            cluster["top_hint_combo"],
            cluster["example"],
        ]
        for cluster in residual_analysis.get("clusters", [])
    ]
    chinese_residual_summary = explainability_summary.get("chinese_unsafe_residual_summary") or {}
    chinese_residual_rows = [
        [subtype["label"], str(subtype["count"])]
        for subtype in chinese_residual_summary.get("subtypes", [])
    ]

    content = f"""# 评测报告 - {run_name}

## 项目背景

本项目面向大模型应用防火墙运营策略场景，目标是建设一条从样本沉淀、规则检测、基线分类、批量评测到误报漏报归因与报告输出的闭环链路。重点覆盖 prompt injection、jailbreak、敏感信息套取、角色劫持、工具误用与 RAG 间接注入。

## 测试范围

- 评测运行 ID：`{run_id}`
- 样本总量：`{sample_distribution['total']}`
- 攻击/对抗样本：`{sample_distribution['risky']}`
- 白样本：`{sample_distribution['benign']}`
- 攻击类型分布：`{sample_distribution['by_category']}`

## 样本分布

{_markdown_table(["维度", "值"], [[key, str(value)] for key, value in sample_distribution.items() if key not in {"by_category", "by_language"}])}

### 语言分布

{_markdown_table(["语言", "样本数"], [[key, str(value)] for key, value in sample_distribution.get("by_language", {}).items()])}

## 各策略结果对比

{_markdown_table(["策略", "Precision", "Recall", "F1", "FPR", "FNR", "人工复核率", "平均时延(ms)"], comparison_rows)}

## 中英分开评测

当前聚焦策略：`{focus_strategy_name}`

### 按语言聚合

{_markdown_table(["语言", "Precision", "Recall", "F1", "样本数"], language_rows)}

### 重点语言场景矩阵

{_markdown_table(["切片", "样本数", "Precision", "Recall", "F1"], focus_matrix_rows)}

### 英文直攻互斥专项分桶

{_markdown_table(["专项", "样本数", "Precision", "Recall", "F1"], english_direct_subslice_rows)}

### 中文 unsafe_prompt 专项分桶

{_markdown_table(["专项", "样本数", "Precision", "Recall", "F1"], chinese_unsafe_subslice_rows)}

## 阈值扫描

{_markdown_table(["策略", "最佳拦截阈值", "最佳复核阈值", "最佳 F1"], threshold_rows)}

## 典型误报案例

以下案例来自当前聚焦策略：`{focus_strategy_name}`

{_markdown_table(["样本类型", "判定", "攻击类别", "文本片段"], fp_rows)}

## 典型漏报案例

以下案例来自当前聚焦策略：`{focus_strategy_name}`

{_markdown_table(["样本类型", "判定", "攻击类别", "文本片段"], fn_rows)}

## 误报漏报归因

以下归因统计来自当前聚焦策略：`{focus_strategy_name}`

{_markdown_table(["归因标签", "数量"], attribution_rows)}

## 可解释性摘要

{_markdown_table(["指标", "值"], explainability_rows)}

### classifier-only 误报 Hint 组合

{_markdown_table(["Hint 组合", "数量"], classifier_only_hint_rows)}

### 稳定误报模式

{_markdown_table(["模式", "数量"], stable_false_positive_rows)}

### 英文间接注入残余漏报子归因

剩余英文间接注入漏报总数：`{indirect_residual_summary.get("total_residual_false_negatives", 0)}`

{_markdown_table(["子归因", "数量", "示例片段"], indirect_residual_rows)}

### 英文直攻残余漏报聚类

剩余英文直攻漏报总数：`{residual_analysis.get("total_residual_false_negatives", 0)}`

{_markdown_table(["聚类", "数量", "主导 Hint 组合", "示例片段"], residual_rows)}

### 中文 unsafe_prompt 剩余漏报池

剩余中文 unsafe_prompt 漏报总数：`{chinese_residual_summary.get("total_residual_false_negatives", 0)}`

classifier 高分但低证据：`{chinese_residual_summary.get("classifier_high_score_but_low_evidence", 0)}`

规则命中但可执行性不足：`{chinese_residual_summary.get("rule_hit_but_not_actionable_enough", 0)}`

harmful_operational_guidance 非结构化尾巴：`{chinese_residual_summary.get("harmful_operational_guidance_unstructured", 0)}`

{_markdown_table(["子类", "数量"], chinese_residual_rows)}

### 中文 harmful_operational_guidance 非结构化表达方式

{_markdown_table(["表达方式", "数量"], [[item["label"], str(item["count"])] for item in chinese_residual_summary.get("expression_clusters", [])] or [["无", "0"]])}

## 调优建议

1. 对 `indirect_prompt_injection` 场景单独配置更严格的上下文规则，并增加“忽略检索文本中元指令”的模板检测。
2. 对命中“系统提示词”“导出密钥”等高危规则的样本直接阻断，对模糊规则仅进入人工复核，降低误报。
3. 继续扩充办公助手、知识库问答、代码助手场景白样本，提升分类器对局部重叠文本的泛化能力。
4. 为输出侧过滤引入更多数据外传与权限提升规则，减少模型响应阶段的二次风险。

## 后续迭代方向

1. 将基线分类器替换为蒸馏版中文文本分类模型，验证在成本可控前提下的收益。
2. 引入规则命中权重学习与在线阈值调参，支持不同业务线策略分层。
3. 增加样本标注工作流与 reviewer 审核闭环，强化运营沉淀能力。
4. 扩展 PostgreSQL、对象存储与异步任务队列，支持更大规模评测。
"""
    Path(report_path).write_text(content, encoding="utf-8")
    return str(report_path), content
