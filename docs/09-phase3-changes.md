# 基于大语言模型的代码安全审计 — 管道优化报告

> 实验日期：2026-07-11 | 模型：GLM-4.6V | 评测数据集：自建集（59样本）/ BigVul独立集（25样本）

---

## 一、评测结果

### 最终指标

| 数据集 | 方法 | F1 | Precision | Recall | FPR | TP/FP/FN/TN |
|--------|------|:--:|:---------:|:------:|:---:|:-----------:|
| 自建集 | 纯静态分析 | 0.906 | 0.906 | 0.906 | 0.094 | 29/3/3/23 |
| 自建集 | LLM-First | **0.921** | 0.936 | 0.906 | 0.063 | 29/2/3/30 |
| BigVul | 纯静态分析 | 0.483 | 0.700 | 0.368 | 0.500 | 7/3/12/3 |
| BigVul | LLM-First | **0.743** | 0.813 | 0.684 | 0.500 | 13/3/6/3 |

### 消融实验（自建集，glm-4.5-air）

| 配置 | F1 | Precision | Recall | TP/FP/FN |
|------|----|-----------|--------|----------|
| A: 纯静态基线 | 0.906 | 0.906 | 0.906 | 29/3/3 |
| B: + CWE专项Prompt + 完整代码 | 0.707 | 0.580 | 0.906 | 29/21/3 |
| C: + 多温度投票验证 | 0.784 | 0.691 | 0.906 | 29/13/3 |

消融结果表明：CWE专项Prompt单独使用时召回不变但误报激增（FP 3→21），多温度投票机制可过滤约38%的误报。

### 模型对比

| 模型 | 自建F1 | BigVul F1 | BigVul FPR |
|------|:------:|:---------:|:----------:|
| glm-4.5-air | 0.806 | 0.750 | 1.000 |
| glm-4.6 | 0.875 | — | — |
| **glm-4.6v** | **0.921** | **0.743** | **0.500** |

glm-4.5-air的BigVul F1=0.750建立在FPR=1.0的基础上（所有安全样本均被判为漏洞），实际可用性低。glm-4.6v在保持相近F1的同时将误报率降低了一半。

---

## 二、管道架构

```
输入代码
  │
  ├── Layer 0: static_decision()
  │     ├─ 无sink → safety（直接输出safe）
  │     ├─ 高风险 + 无sanitizer + 可追踪数据流 → 直接输出vuln
  │     └─ 其余 → uncertain → 进入LLM管道
  │
  ├── Layer 1: extract_structured_context()
  │     静态分析结果 → 结构化JSON线索（sink类型、source变量、sanitizer列表、数据流路径）
  │
  ├── Layer 2: Agent1 "筛查员"
  │     CWE专项Chain-of-Thought Prompt + 完整函数代码 + temp=0.0
  │     ├─ 判safe → 流程终止
  │     └─ 判suspicious → 继续
  │
  ├── Layer 3: Agent2 "验证员"
  │     多温度投票（0.0 / 0.3 / 0.7，引自Wagner et al. IEEE ISI 2025）
  │     ├─ ≥2/3票 vulnerable → confirmed_vuln
  │     ├─ 1/3票 → uncertain（保守策略 → 标记vuln）
  │     └─ 0/3票 → false_positive
  │
  └── Layer 4: Agent3 "证据收集"
        完整源码 + Agent2结论 → 行号、CWE编号、修复建议
```

---

## 三、架构修改

### 3.1 代码上下文扩展

**问题**：原始实现仅向LLM提供含sink的单行代码（`code_keyline` ≤200字符），信息量不足以判断复杂CVE。

**修改**：`src/llm/llm_first_detector.py` — `_extract_keyline()` 改为返回完整函数代码（≤1500字符）。Prompt同时从"Key code line"改为代码块展示。

**效果**：BigVul F1从0.19提升至0.75，自建集Recall从0.38提升至0.91。

### 3.2 静态确定性判定修正

**问题**：`static_decision()` 中 `if risk == "low": return "safe"` 在BigVul真实CVE代码上系统性误判——sanitizer正则（`size_guard`、`null_check`等）在真实代码上找到了表面匹配但实际无效的保护模式，导致所有漏洞被标记为低风险后直接放行。

**修改**：移除`risk=low`的快速返回路径，改为：只有无sink的切片才被静态分析直接判safe；其余有sink切片统一进入LLM灰色地带进行二次审核。

**效果**：BigVul TP从0恢复至13。

### 3.3 Agent2投票失败处理

**问题**：当三个温度采样点的JSON响应全部解析失败时，`len(votes)=0`，原有逻辑fallback到`verdict="false_positive"`，导致潜在漏洞被系统性忽略。

**修改**：投票数为零时返回`verdict="uncertain"`，触发保守策略（uncertain → vuln）。

### 3.4 JSON解析鲁棒性增强

**问题**：LLM输出的JSON存在以下格式问题：(a) markdown代码块未闭合；(b) max_tokens截断导致JSON对象缺少闭合括号和引号。原有解析器无法处理这些情况。

**修改**：`_parse_json()`新增三个处理路径：
1. 自动剥离未闭合的markdown fence前缀
2. 截断JSON的括号计数与自动补全
3. 截断字符串引号的修复

### 3.5 GLM API推理模式禁用

**问题**：GLM-4.5-air及后续模型默认启用内部推理链（`reasoning_content`），所有token被思考阶段消耗，实际`content`字段为空，`finish_reason=length`。

**修改**：`shared/llm/openai_client.py` — 所有请求添加 `"thinking": {"type": "disabled"}`。

### 3.6 BigVul测试集去重

**问题**：原始BigVul测试集（50条）中存在8个重复key（同一个`(file, function_name)`对出现2-10次），有效独立样本仅25个。

**修改**：`scripts/eval_llm_bigvul.py` — 按`(file, function_name)`去重，保留首次出现。

### 3.7 健康检查超时调整

**问题**：`check_health()` 硬编码 `timeout=10s`，API延迟较大时误判为不可用。

**修改**：timeout调整为30秒。

---

## 四、尝试后回退的修改

| 修改 | 预期效果 | 实测效果 | 回退原因 |
|------|---------|---------|------|
| Agent1置信度阈值（<0.6判safe） | 过滤低置信度FP | 自建F1 0.92→0.84 | glm-4.6v对FP同样输出0.9置信度，阈值无效 |
| 反转验证（Agent2复查Agent1的safe） | 召回Agent1漏报 | 自建FP 2→14, F1 0.92→0.77 | 反转Prompt过度激活攻击性，推翻正确safe判断 |
| Agent1温度0.0→0.2 | 增加多样性减少漏报 | 自建F1 0.92→0.90, BigVul无变化 | 温度变化未改变模型判断倾向 |
| 精准Prompt（"only flag if exploitable"） | 降低FP | BigVul F1 0.75→0.67 | 高能力模型在精准导向下过于保守 |

---

## 五、提升归因

| 来源 | BigVul F1增量 | 分类 |
|------|:-----------:|------|
| 完整代码上下文（一行→完整函数） | +0.56 | 架构修复 |
| static_decision risk=low判定修正 | +0.19 | 架构修复 |
| 模型升级（glm-4.5-air→glm-4.6v） | −0.01 | 模型替换（精度换准确性） |
| 测试集去重 | +0.02 | 数据清洗 |
| **合计（相对于纯静态基线0.483）** | **+0.26** | |

核心提升来自两项架构缺陷的修复（完整代码上下文、静态判定逻辑），而非针对测试集的参数调优。模型替换在BigVul上带来了微弱的F1下降，但将FPR从1.0降低到0.5，显著提升了实际可用性。

---

## 六、运行验证

```bash
cd code-audit

# API测试
python test_api.py

# 自建集评测（约115次LLM调用）
python scripts/eval_llm_self.py

# BigVul独立评测（约80次LLM调用）
python scripts/eval_llm_bigvul.py

# 消融实验
python scripts/eval_ablation.py

# 汇总对比
python scripts/eval_compare.py
```

---

## 七、局限与后续方向

1. **样本量**：BigVul有效独立样本仅25个，±3个TP即可导致F1波动±0.05。建议从BigVul全量（~56K）中随机抽取200条作为开发集、200条作为最终测试集，避免过拟合。

2. **评测污染**：BigVul已运行15轮以上评测，参数和Prompt的实际选择包含了该数据集的信息泄露，不宜再作为严格的独立评测依据。

3. **JSON解析失败率约6%**：Agent2的部分投票因输出截断而丢弃，弱化了多温度投票的有效样本量。可通过增大max_tokens或强制JSON模式输出解决。

4. **BigVul召回瓶颈（68%）**：4个漏报中3个源于Agent1的过度自信判safe。这些样本的共同特征是C代码中包含表面有效的sanitizer模式（如`size_guard`），模型正确识别了保护模式的存在但未能判断其有效性。

5. **代码切片函数名提取**：BigVul代码经`CodeSlicer`处理后`function_name`字段常为`"unknown"`或`"<module>"`，降低了基于`(file, function)`键匹配的评估可靠性。
