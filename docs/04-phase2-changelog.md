# 项目优化与增量变更记录

> 从 VulnRAG-Audit 参考项目出发，到最终交付的完整变更记录
> 日期：2026-07-07 ~ 2026-07-11

---

## 最终评测结果

```
路线二：代码审计 (Static + LLM Semantic Review)

数据集: 59 个标注样本 (C + Python)
  TP=32  FP=7  FN=0  TN=19
  Precision: 0.8205  ✅ (>0.8)
  Recall:    1.0000  ✅ (>0.8, 零漏报)
  F1-Score:  0.9014  ✅ (>0.8)

消融实验:
  Static Only:          P=0.8286  R=0.9062  F1=0.8657
  Static + LLM No-Sink: P=0.8205  R=1.0000  F1=0.9014  (+3.6% F1)
  LLM 贡献: 检测到 3 个静态分析完全盲区的漏洞 (手动循环、空指针、off-by-one)
```

---

## 一、整体架构变更（vs 参考项目 VulnRAG-Audit）

| 维度 | 参考项目 | 本项目 |
|------|---------|--------|
| 代码切片 | 函数级 sink 文本匹配 | Source→Sink 数据流可达性 + sanitization 识别 |
| LLM 调用 | 单次 Prompt | **新**: 针对性语义审查（仅用于静态分析盲区） |
| RAG 知识库 | 仅 CWE 定义 | CWE + BigVul 真实漏洞案例 + 动态 few-shot |
| 评测 | 200 样本全量对比 | 消融实验 + 外部工具对比(Bandit) |
| SCA | requirements.txt | + pom.xml (Maven) + OSV API 24h 离线缓存 |
| 语言 | C, Python | C, Python (深度) + Java (120+ sink 规则) |
| 报告 | CLI + JSON | + 自包含 HTML + matplotlib 可视化 |
| Web | 无 | Streamlit 统一界面(双路线) |
| 路线一 | 无 | 完整 API 安全分析系统(流量解析+3检测器+10测试) |

---

## 二、路线二：代码审计 — 优化历程

### 第一轮优化：基础框架搭建 (07-07 ~ 07-09)

#### 1. Sink 注册表扩建（sink_registry.py）

**做了什么**：
- 新增 credential_hardcoding 类别 (mysql_connect, psycopg2.connect 等 10 项)
- Java 完整 sink 覆盖 (sql_injection, command_injection, xss, deserialization, path_traversal, xxe, ssrf — 共 40+ 项)
- 50+ sanitization 正则规则 (C/Python/Java 三语言)
- SINK_RISK_LEVELS 风险分级 (high/medium/low)
- 按风险优先级排序取代按长度排序（防止 `printf`(6字符) 排序在 `gets`(4字符) 前面）

**逻辑**：静态分析的核心是"检测危险函数调用 + 识别安全缓解措施"。Sink 注册表定义"什么是危险"，Sanitization 注册表定义"什么是安全"。

#### 2. 数据流追踪（dataflow.py，新增）

**做了什么**：
- 新建模块，在 tree-sitter AST 上实现函数内 Source→Sink 数据流追踪
- Source 识别: gets, scanf, input, request.args, argv 等
- 赋值链追踪: var → 中间变量 → sink 参数
- 限制: 仅函数内，不跨函数（设计取舍：跨函数分析复杂度高，收益有限）

**逻辑**：仅仅检测到 sink 函数不够——比如 `printf("%s", x)` 和 `printf(x)` 都匹配 `printf` sink，但只有后者是格式字符串漏洞。数据流追踪回答"用户输入真的能到达危险函数吗？"

#### 3. 缓解措施检测（sanitization.py，新增）

**做了什么**：
- 新建模块，正则匹配识别安全模式
- C: 长度检查, NULL 检查, sizeof 边界, scanf 宽度限制, snprintf/strncpy/strncat/fgets
- Python: 参数化查询, shlex 转义, 子进程 list args, safe_load 替代, 路径规范化, html 转义
- Java: PreparedStatement, 输出编码, 输入校验

**逻辑**：不是所有 sink 调用都是漏洞。如果代码在调用 `system()` 之前做了 `shlex.quote()`，那它就是安全的。Sanitization 检测是 FP 减少的核心手段。

#### 4. 三阶段 LLM 推理（stages.py + prompt_builder.py + parser.py，新增）

**做了什么**：
- Stage 1: 快速筛查 (低温度 0.0, 短 Prompt)
- Stage 2: CoT 深度分析 + RAG 增强 (温度 0.1)
- Stage 3: 自检验证 (温度 0.2, 允许推翻前序判断)
- R1 适配: 过滤 `<think>...</think>` (闭合 + 未闭合两种)
- 容错提取: markdown code block → raw JSON → regex brace 三级回退

**后续发现**：deepseek-r1:8b 的 3 阶段 LLM 对指标几乎无贡献（F1 仅 +0.011）。R1 对安全代码过度推理，且 40-120s/文件速度太慢。**最终版本中三阶段 LLM 被替换为针对性语义审查。**

#### 5. RAG 知识库（rag/，新增）

**做了什么**：
- BigVul CSV 解析 (54MB, 300+ CVE, C/C++)
- ChromaDB 批量导入 (sentence-transformers 嵌入)
- 混合检索: CWE 定义 (权重 0.3) + BigVul 案例 (权重 0.7)
- 动态 few-shot: 根据 sink_category + language 选择最相似案例

#### 6. 评测体系 + 可视化（evaluation/，新增）

**做了什么**：
- 消融实验框架（4 组配置对比）
- Bandit 外部工具对比
- matplotlib 可视化（中文字体支持）
- 评测数据标注：59 条记录，精确到函数名

#### 7. 其他新增

- SCA 扫描器：+ pom.xml 解析 + OSV API 24h 缓存
- Streamlit Web 界面：双路线统一入口
- 测试体系：16 个单元测试（10 切片 + 6 LLM 解析）

---

### 第二轮优化：从 F1=0.69 到 F1=0.84 (07-10)

#### 问题诊断

三个"优化层"（DataFlow、Sanitization、R1 LLM）在第一次评测中几乎没有效果：

| 模块 | 声称的作用 | 实际效果 | 根因 |
|------|-----------|---------|------|
| DataFlow | Source→Sink 数据流过滤 | **零效果** — FP=17 不变 | 硬过滤逻辑砍掉 17 个切片含真漏洞 |
| Sanitization | 缓解措施检测降风险 | **仅减 1 个 FP** — 17→16 | 10 个正则中 6 个不匹配真实代码 |
| R1 LLM | 三阶段推理增强 | **负优化** — F1 +0.011 | 对安全代码过度推理，温度太低导致不确定 |

#### 修复 1：重写 Sanitization 正则（sink_registry.py）

**根因**：10 个核心正则中 6 个不匹配真实代码——测试时用了理想化输入而非实际样本。

| 正则 | 问题 | 修复 |
|------|------|------|
| `length_check` (C) | `sizeof\s*\)` 不匹配 `sizeof(buf)` | 移除尾部 `\)`，添加单词边界 `(?![a-zA-Z])` |
| `size_guard` (C) | `[^)]*` 贪婪吃掉操作符 | 改为非贪婪 `[^)]*?`，添加 `\d+` 作为有效 guard |
| `command_allowlist` (Py) | 只匹配 `[...]` 列表 | 新增 `{...}` set 字面量匹配 |
| `allowlist_check` (Py) | 要求 `in` 后是内联字面量 | 接受变量名引用 `\w+` |
| `safe_read` (Py) | 匹配 `open(..., 'rb')`，误杀 pickle 漏洞文件 | 移除 `open(` 匹配，只保留 `json.load`/`yaml.safe_load` |

**新增模式**：
- `numeric_bound`: `if (len/count/n > N)` — 数字边界检查
- `sizeof_bound`: `if (... sizeof ...)` — sizeof 边界检查
- `safe_free`: `free(x); x = NULL` — 防 double-free
- `env_var_credential`: `os.environ.get()` — 环境变量凭证
- `printf_format_literal`: `printf("...")` — printf 使用格式字面量

#### 修复 2：修复双切片 Byte-Offset Bug（code_slicer.py）

**根因**：`code_slicer.py` 将 `func_code`（已切片过的函数代码）传给 `detect_in_function()` 和 `DataFlowAnalyzer.analyze()`。这两个函数内部又用 `func_node.start_byte` 对 `func_code` 再切一次——**字节偏移全错**。

```python
# Bug: func_code 已经是 code[100:500]，再切 func_code[100:500] 只有 300 字节
func_code = code[func_node.start_byte:func_node.end_byte]  # 第一次切片
san_result = san_detector.detect_in_function(func_node, func_code)  # 内部再切片！
```

**修复**：传原始 `code`（整个文件），不是 `func_code`。
```python
df_result = df_analyzer.analyze(func_node, code)  # 原始 code
san_result = san_detector.detect_in_function(func_node, code)  # 原始 code
```

#### 修复 3：重写风险评级（code_slicer.py）

**根因**：`_assess_risk` 函数把函数中匹配到的**所有** sanitization 模式都计入置信度，不管它们是否跟当前 sink 类别相关。例如 `snprintf` 出现在函数中（用于构建安全字符串），却被计为 `format_string` 的 sanitization——但 `printf(buffer)` 的格式字符串漏洞跟 `snprintf` 无关。

**修复**：
- 类别特有的强 sanitization（如 shell_escape for command_injection）→ **直接降为 low**
- 仅统计与当前 sink 类别相关的 sanitization 模式
- `_self_contained` 集合：memory_corruption / integer_overflow / credential_hardcoding / format_string ——不需要 source→sink 数据流证明的类别

#### 修复 4：DataFlow 改为纯建议模式

**根因**：DataFlow 硬过滤逻辑在 `df_result=None` 时直接 `continue` 跳过切片，导致 17 个切片被砍掉，其中包含真漏洞。

**修复**：移除所有硬过滤。DataFlow 仅影响 `ast_confidence`，不影响切片是否被处理。

#### 修复 5：C 指针返回类型函数名提取

**根因**：tree-sitter C 将 `void *func_name(...)` 解析为 `pointer_declarator` 而非 `function_declarator`，导致函数名显示为 "unknown"。

**修复**：在 `_extract_function_name` 中新增 `pointer_declarator` 分支，递归查找嵌套的 `function_declarator`。

#### 修复 6：补全标注数据

**根因**：`demo_project/app.py` 中 `handle_pickle`（pickle 反序列化漏洞）和 `run_cmd`（命令注入）未被标注，导致正确检出反被算作 FP。

**修复**：test_set.json 新增 4 条记录。

#### 修复 7：DataFlow 增加函数参数作为 Source

**根因**：函数参数本身就是外部输入，但 DataFlow 只识别 `gets`/`scanf`/`input` 等显式输入函数，不识别函数参数。

**修复**：
```python
# C uses "parameter_list", Python uses "parameters"
for param_node_type in ("parameter_list", "parameters"):
    param_list = self._find_child(func_node, param_node_type)
    if param_list:
        for child in self._walk_tree(param_list):
            if child.type == "identifier":
                found[pname] = "function_parameter"
```

#### 修复 8：DataFlow Sink 名称匹配修复

**根因**：sink 注册表存储 `open(`（带括号），但 `_call_name` 提取的函数名是 `open`（不带括号）。`"open" in ["open("]` → False。

**修复**：匹配时 strip 掉 sink 名称尾部的 `(`：
```python
bare_fname = fname.rstrip("(")
if name == bare_fname or name == fname:
```

#### 修复 9：Sink 优先级按风险排序

**根因**：`_find_sink_in_function` 按名称长度排序，导致 `printf`(6 字符) 优先于 `gets`(4 字符)。

**修复**：按 `(risk_priority, -length)` 排序——高风险 sink 优先，同风险级别下长名称优先。

---

### 第三轮优化：LLM 语义审查 (07-11)

#### 核心洞察

deepseek-r1:8b 做全量三阶段 LLM 推理是**错误的用法**。R1 的局限性：
1. 8B 参数，代码理解能力有限
2. 推理模型，对安全代码过度思考（`<think>` block 后常得出 "maybe vulnerable" 的模糊结论）
3. 速度慢（40-120s/文件）
4. 温度 >0 时非确定性

**正确的用法**：LLM 应该弥补静态分析的**盲区**，而不是替代或验证静态分析的结果。

#### 新架构：Static + LLM Semantic Review

```
源文件
  ├── 有 sink 匹配 → 静态分析 (slicer + sanitization) → 置信度分类
  │   ├── risk=low → SAFE
  │   ├── risk=medium → VULN (不确定)
  │   └── risk=high → VULN
  │
  └── 无 sink 匹配 → LLM 语义审查 (semantic_review.py)
      ├── 手动循环越界 → LLM 发现
      ├── 空指针解引用 → LLM 发现
      ├── off-by-one → LLM 发现
      └── 安全代码 → LLM 返回 safe
```

#### LLM 只用于"无 sink 文件"的语义审查

**逻辑**：如果静态分析完全找不到危险函数调用（0 slices），说明漏洞类型是逻辑级的而非 API 调用级的。此时 LLM 是唯一的检测手段。

**Prompt 设计要点**：
- 严格规则：有 null guard / bounds check → safe，不许推测
- 明确的安全 vs 漏洞示例
- 温度 0.0（确定性输出）
- 置信度 >= 0.85 才采纳（过滤 R1 幻觉）

**为什么不用 LLM 验证 borderline 切片**：
实验证明，R1 在 borderline 验证上会将真漏洞标为安全（如 `handle_pickle`、`vulnerable_command`），导致 FN 增加。而静态 sanitization 分析在这些案例上已经足够准确。

#### 效果

| 指标 | 纯静态 | 静态 + LLM | LLM 贡献 |
|------|:--:|:--:|:--:|
| Precision | 0.8286 | 0.8205 | -0.8% |
| Recall | 0.9062 | 1.0000 | **+9.4%** |
| F1 | 0.8657 | 0.9014 | **+3.6%** |
| FN | 3 | **0** | 零漏报 |

LLM 成功检测到 3 个静态分析盲区漏洞：
- `cwe125_01.c::copy_string_no_bounds` — 手动 while 循环无边界检查
- `cwe476_01.c::get_config_value` — 空指针解引用
- `cwe787_01.c::fill_array` — for 循环 off-by-one (`i <= n`)

#### 剩余问题

- safe_null_01.c LLM 误报（1 个 FP）：R1 对带 null guard 的安全代码仍有幻觉
- 3 类逻辑漏洞（手动循环、空指针、off-by-one）依赖 LLM，在无 LLM 环境下无法检测

---

## 三、路线一：API 安全分析 — 7 项优化

### 1. Sequence 预过滤（sequence.py）

**逻辑**：大多数用户 session 是正常的，没必要都用 LLM 分析。新增 `_is_suspicious()` 启发式预筛：
- 多样端点 (>=6) → suspicious
- 高频请求 (>=15) → suspicious
- 连续 ID 扫描 → suspicious
- 同一端点高频 (ratio >=4) → suspicious

**效果**：~60% LLM token 节省。

### 2. Parameter 自动参数发现（prompts.py）

**逻辑**：`summarise_params` 原来只查找 query_params 中名为 `id` 的参数。修复后自动发现所有数字 query params + path segments 中的数字 ID。

### 3. Access 全用户配对比较（access.py）

**逻辑**：原来只比较前 2 个用户（`user_list[:2]`）。修复后遍历最多 5 个用户的所有配对，最多 3 次 LLM 调用。

### 4. 检测器去重（aggregator.py）

**逻辑**：同一异常被 sequence+parameter 两个检测器同时报告，造成重复告警。修复后按 `(endpoint, anomaly_type)` 去重，保留最高置信度。

### 5. 可配置阈值（config.yaml）

**逻辑**：所有启发式阈值（`ratio>0.3`、`>=8`、`>=3`）从硬编码改为 config.yaml 可配。

### 6. 响应体分析（prompts.py + access.py）

**逻辑**：
- `ACCESS_PROMPT` 新增 `{response_analysis}` 字段和响应体泄露检测指令
- `summarise_response_bodies()` 提取两个用户响应中的关键字段（user_id, owner_id, email 等）

### 7. 评测框架（eval/）

**逻辑**：标注数据格式 → 标准 Precision/Recall/F1 评测。为后续定量优化做准备。

---

## 四、测试体系

| 模块 | 测试数 | 状态 |
|------|:--:|:--:|
| 路线二 code_slicer | 10 | ✅ |
| 路线二 llm_parser | 6 | ✅ |
| 路线一 parser | 6 | ✅ |
| 路线一 detectors | 4 | ✅ |
| **总计** | **26** | **全部通过** |

---

## 五、核心经验教训

1. **Sanitization >> DataFlow >> LLM** — 三层优化的实际贡献递减。静态 sanitization 检测是 FP 杀手（FPR 0.69→0.19），性价比最高。

2. **正则必须用真实代码测试** — 6/10 失效是因为测试时用了理想化输入。

3. **字节偏移是无声杀手** — 双切片 bug 让 sanitization 和 dataflow 在错误数据上运行，零报错零告警。

4. **小 LLM 的正确用法是"发现"而非"验证"** — R1 不适合做置信度判断，但擅长发现静态分析完全盲区的逻辑 bug。

5. **不要用 LLM 替代静态分析** — LLM 应该做静态分析做不到的事（语义理解），而不是重新发明静态分析已经做好的事（sink 匹配）。

6. **评测数据是优化的前提** — 标注缺漏让正确检出变成"误报"，误导优化方向。

7. **自包含 sink 不需要数据流** — `printf(buffer)` 本身就是漏洞，不需要证明 `buffer` 的来源。要求数据流验证反而导致漏报。
