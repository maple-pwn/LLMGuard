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

    full_stack = metrics.get("full_stack") or next(iter(metrics.values()))
    attribution_rows = [
        [label, str(count)] for label, count in (full_stack.get("attribution_summary") or {}).items()
    ]
    fp_rows = [
        [case["sample_type"], case["decision"], case["attack_category"] or "-", case["text"][:40]]
        for case in full_stack.get("typical_false_positives", [])
    ]
    fn_rows = [
        [case["sample_type"], case["decision"], case["attack_category"] or "-", case["text"][:40]]
        for case in full_stack.get("typical_false_negatives", [])
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

{_markdown_table(["维度", "值"], [[key, str(value)] for key, value in sample_distribution.items() if key != "by_category"])}

## 各策略结果对比

{_markdown_table(["策略", "Precision", "Recall", "F1", "FPR", "FNR", "人工复核率", "平均时延(ms)"], comparison_rows)}

## 阈值扫描

{_markdown_table(["策略", "最佳拦截阈值", "最佳复核阈值", "最佳 F1"], threshold_rows)}

## 典型误报案例

{_markdown_table(["样本类型", "判定", "攻击类别", "文本片段"], fp_rows)}

## 典型漏报案例

{_markdown_table(["样本类型", "判定", "攻击类别", "文本片段"], fn_rows)}

## 误报漏报归因

{_markdown_table(["归因标签", "数量"], attribution_rows)}

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
