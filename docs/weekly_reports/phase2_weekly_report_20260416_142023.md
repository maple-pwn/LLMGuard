# 周报 - phase2_weekly_report

## 本周新增样本数

92

## 攻击类型分布变化

{'direct_prompt_injection': 6, 'jailbreak': 7, 'sensitive_info_exfiltration': 11, 'role_override': 8, 'tool_misuse_attempt': 6, 'benign': 39, 'indirect_prompt_injection': 15}

## 误报主要问题

{}

## 漏报主要问题

{}

## 规则更新摘要

本周更新规则数：12

## 阈值调整建议

{'rules_only': {}, 'rules_classifier': {'best_f1': 0.8813559322033898, 'best_block_threshold': 0.65, 'best_review_threshold': 0.5}, 'full_stack': {'best_f1': 0.8907563025210083, 'best_block_threshold': 0.65, 'best_review_threshold': 0.5}, 'full_stack_balanced_v2': {'best_f1': 0.8907563025210083, 'best_block_threshold': 0.65, 'best_review_threshold': 0.5}, 'full_stack_strict_v2': {'best_f1': 0.8907563025210083, 'best_block_threshold': 0.65, 'best_review_threshold': 0.5}, 'rules_classifier_relaxed_v2': {'best_f1': 0.8813559322033898, 'best_block_threshold': 0.65, 'best_review_threshold': 0.5}}

## 下周工作计划

1. 补充边界样本与迷惑性白样本。
2. 对高误报规则进行语义收紧与权重微调。
3. 对重点攻击类型继续做阈值扫描和规则组合对比。
