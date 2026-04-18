# 评测报告 - external_bipia_email_indirect_subset_v2

## 项目背景

本项目面向大模型应用防火墙运营策略场景，目标是建设一条从样本沉淀、规则检测、基线分类、批量评测到误报漏报归因与报告输出的闭环链路。重点覆盖 prompt injection、jailbreak、敏感信息套取、角色劫持、工具误用与 RAG 间接注入。

## 测试范围

- 评测运行 ID：`41`
- 样本总量：`800`
- 攻击/对抗样本：`750`
- 白样本：`50`
- 攻击类型分布：`{'benign': 50, 'indirect_prompt_injection': 750}`

## 样本分布

| 维度 | 值 |
| --- | --- |
| total | 800 |
| risky | 750 |
| benign | 50 |

### 语言分布

| 语言 | 样本数 |
| --- | --- |
| en | 800 |

## 各策略结果对比

| 策略 | Precision | Recall | F1 | FPR | FNR | 人工复核率 | 平均时延(ms) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| rules_only | 1.000 | 0.821 | 0.902 | 0.000 | 0.179 | 0.380 | 1.23 |
| rules_classifier | 1.000 | 0.937 | 0.968 | 0.000 | 0.063 | 0.489 | 3.29 |
| full_stack | 1.000 | 0.937 | 0.968 | 0.000 | 0.063 | 0.489 | 3.37 |
| context_hardened_v3 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0.485 | 3.18 |

## 中英分开评测

当前聚焦策略：`context_hardened_v3`

### 按语言聚合

| 语言 | Precision | Recall | F1 | 样本数 |
| --- | --- | --- | --- | --- |
| en | 1.000 | 1.000 | 1.000 | 800 |

### 重点语言场景矩阵

| 切片 | 样本数 | Precision | Recall | F1 |
| --- | --- | --- | --- | --- |
| English indirect injection | 750 | 1.000 | 1.000 | 1.000 |
| English direct injection | 0 | - | - | - |
| Chinese jailbreak | 0 | - | - | - |
| Chinese benign overlap | 0 | - | - | - |
| Chinese RAG off-topic benign | 0 | - | - | - |

### 英文直攻互斥专项分桶

| 专项 | 样本数 | Precision | Recall | F1 |
| --- | --- | --- | --- | --- |
| PWNED variants | 0 | - | - | - |
| Payload rewrite | 0 | - | - | - |
| Obfuscation | 0 | - | - | - |
| Backslash / separator smuggling | 0 | - | - | - |
| Unstructured / weird variants | 0 | - | - | - |

## 阈值扫描

无


## 典型误报案例

以下案例来自当前聚焦策略：`context_hardened_v3`

无


## 典型漏报案例

以下案例来自当前聚焦策略：`context_hardened_v3`

无


## 误报漏报归因

以下归因统计来自当前聚焦策略：`context_hardened_v3`

无


## 可解释性摘要

| 指标 | 值 |
| --- | --- |
| 办公编辑去歧义触发数 | 0 |
| classifier-only 误报数 | 0 |

### classifier-only 误报 Hint 组合

无


### 稳定误报模式

无


### 英文间接注入残余漏报子归因

剩余英文间接注入漏报总数：`0`

无


### 英文直攻残余漏报聚类

剩余英文直攻漏报总数：`0`

无


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
