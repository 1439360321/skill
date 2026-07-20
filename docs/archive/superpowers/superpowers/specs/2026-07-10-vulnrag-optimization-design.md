# VulnRAG-Audit 优化设计文档

> 基于参考项目 [huoma999/VulnRAG-Audit](https://github.com/huoma999/-) 的全面升级方案
> 目标：LLM 驱动的代码安全漏洞检测，评测数据可写进论文

## 约束条件

- 团队：3 人，无分工，按顺序推进
- 周期：3 周（2026-07-07 起）
- LLM：仅本地模型（Ollama + DeepSeek-Coder / Qwen-Coder）
- 目标：评测数据好看（F1 高于 CodeQL/Semgrep/Bandit 基线）
- 语言：C、Python（深度） + Java（基础）

---

## 一、架构总览

```
                    目标项目源码
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    依赖扫描 (SCA)   代码切片          语言检测
    requirements.txt  tree-sitter      C/Python
    → 离线CVE缓存     → 数据流路径     → Java(基础)
          │              │
          ▼              ▼
     OSV API        → Source→Sink
    → CVE 缓存       可达性检查
          │         → Sanitization 识别
          │              │
          │              ▼
          │         可疑切片 (带数据流路径)
          │              │
          │    ┌─────────┴─────────┐
          │    ▼                   ▼
          │  Stage 1 LLM        RAG 检索
          │  快速筛查            (ChromaDB)
          │  (安全/可疑)          │
          │    │                 │
          │    ▼                 ▼
          │  Stage 2 LLM ←── 知识增强 Prompt
          │  → CoT深度分析   (CWE + BigVul cases
          │    │                + 动态 few-shot)
          │    ▼
          │  Stage 3 LLM
          │  → 自检验证
          │    │
          │    ▼
          │  结果聚合 + 后处理
          │    │
          └────┴───────→ 评测引擎
                         Baseline / +RAG / +多阶段 / +数据流
                         vs CodeQL / Semgrep / Bandit
                              │
                              ▼
                         报告输出 (HTML / CLI / JSON)
```

**与 VulnRAG-Audit 的关键变化：**

| 维度 | 原版 | 升级版 |
|------|------|--------|
| 代码切片 | 函数级 sink 匹配 | Source→Sink 数据流路径 + sanitization 识别 |
| LLM 调用 | 单次推理 | 三阶段：筛查→深度→自检 |
| RAG 知识库 | 仅 CWE 定义 | CWE + BigVul 真实案例 + 动态 few-shot |
| 评测 | 200 样本全量对比 | 大规模 + 消融实验（每项改进独立增益） |
| SCA | 仅 requirements.txt | + 离线 CVE 缓存（避免 OSV API 瓶颈） |
| 语言支持 | C、Python | C、Python（深度） + Java（基础 sink 覆盖） |

---

## 二、模块详细设计

### 2.1 代码切片升级（优先级：最高）

**当前问题：**
- 只检查函数体内是否包含硬编码 sink 函数名
- 没有 Source→Sink 数据流追踪
- 没有 sanitization 识别
- 大量误报传入 LLM，浪费推理资源

**升级方案：轻量级 Source→Sink 路径可达性**

在 tree-sitter AST 上实现（不引入真实数据流框架），限于函数内分析：

```
算法：
1. AST 遍历，标记 Source 和 Sink 节点
2. Source 变量名 → 赋值链追踪 → Sink 参数子树匹配
3. 在 Source→Sink 路径上检查 sanitization 模式
4. 输出：数据流路径 + 是否有 sanitization + 风险等级
```

**Source 定义：**
```python
SOURCES = {
    "c": {
        "function_calls": ["gets", "scanf", "read", "recv", "fgets", "getenv", "getcwd"],
        "variables": ["argv", "argc"],
        "patterns": ["stdin", "cin"],
    },
    "python": {
        "function_calls": ["input", "getattr", "__import__"],
        "objects": ["request", "request.args", "request.form", "request.json",
                    "request.cookies", "request.headers", "request.files",
                    "os.environ", "sys.argv", "file.read", "open"],
        "patterns": ["socket.recv", "urlopen"],
    },
    "java": {
        "function_calls": [],
        "objects": ["request.getParameter", "request.getQueryString",
                    "request.getHeader", "request.getCookies",
                    "request.getInputStream", "request.getReader",
                    "System.getenv", "args", "javax.servlet"],
        "patterns": ["@RequestParam", "@PathVariable", "@RequestBody"],
    },
}
```

**Sink 定义：**
```python
SINKS = {
    "c": {
        "buffer_overflow": ["strcpy", "strcat", "sprintf", "memcpy", "gets", "scanf", "wcscpy"],
        "command_injection": ["system", "popen", "execve", "execl", "execvp", "CreateProcess"],
        "format_string": ["printf", "fprintf", "snprintf", "syslog"],
        "memory_corruption": ["free", "malloc", "realloc", "memmove", "alloca"],
        "path_traversal": ["fopen", "open", "stat", "access", "chmod"],
        "integer_overflow": [],  # 靠 LLM 语义分析
    },
    "python": {
        "command_injection": ["os.system", "os.popen", "subprocess.call",
                             "subprocess.Popen", "subprocess.run", "subprocess.check_output",
                             "os.exec", "os.spawn", "commands.getoutput"],
        "code_injection": ["eval", "exec", "compile", "__import__"],
        "deserialization": ["pickle.loads", "pickle.load", "yaml.load",
                           "yaml.unsafe_load", "marshal.loads", "dill.loads"],
        "sql_injection": ["cursor.execute", "connection.execute", ".raw(", "execute("],
        "path_traversal": ["open", "os.remove", "os.rename", "shutil.copy",
                          "tarfile.extractall", "zipfile.extractall"],
        "ssrf": ["requests.get", "requests.post", "urllib.request.urlopen",
                "httpx.get", "httpx.post"],
        "xss": ["render_template_string", "Markup", "html."],
    },
    "java": {
        "sql_injection": ["Statement.executeQuery", "Statement.execute",
                         "Statement.executeUpdate", "createStatement",
                         "prepareStatement("],
        "command_injection": ["Runtime.exec", "ProcessBuilder.start", "ProcessBuilder("],
        "xss": ["response.getWriter().write", "response.getWriter().print",
               "<%= ", "out.println("],
        "deserialization": ["ObjectInputStream.readObject", "readObject(",
                           "XMLDecoder.readObject", "XStream.fromXML"],
        "path_traversal": ["FileInputStream", "FileOutputStream", "FileReader",
                          "FileWriter", "File(", "Paths.get"],
        "xxe": ["DocumentBuilder.parse", "SAXParser.parse", "XMLReader.parse",
               "SAXReader.read", "DocumentBuilderFactory.newInstance"],
    },
}
```

**Sanitization 识别：**
```python
SANITIZATION_PATTERNS = {
    "c": [
        # 长度检查
        (r"if\s*\(.*<\s*(?:MAX|SIZE|sizeof|BUFSIZ|LIMIT)", "length_check"),
        (r"snprintf\s*\(.*sizeof", "safe_snprintf"),
        (r"strncpy\s*\(.*sizeof", "safe_strncpy"),
        # 输入校验
        (r"if\s*\(.*\|\|.*\)", "null_check"),  # 过于宽泛，看 LLM 判断
    ],
    "python": [
        (r"\.strip\(\)|\.lstrip\(\)|\.rstrip\(\)", "strip"),
        (r"re\.(sub|escape|match|search)\(", "regex_sanitize"),
        (r"int\(|float\(|str\(|bool\(|list\(|dict\(", "type_cast"),
        (r"shlex\.quote\(|pipes\.quote\(|escape\(", "shell_escape"),
        (r"\.replace\(|html\.escape\(|markupsafe\.escape\(", "xss_escape"),
        # SQL 安全模式
        (r"cursor\.execute\([^,]+,\s*\(|\.execute\([^,]+,\s*\[", "parameterized_query"),
        # 文件路径安全
        (r"os\.path\.(basename|abspath|realpath|normpath)\(", "path_normalize"),
    ],
}
```

**输出格式：**
```python
{
    "function_name": "process_request",
    "code": "void process_request(char* url, char* dest) { ... }",
    "language": "c",
    "line_start": 10,
    "line_end": 30,
    "sink_type": "strcpy",
    "sink_category": "buffer_overflow",
    "source_var": "argv[1]",
    "source_type": "user_input",
    "has_sanitization": True,
    "sanitization_detail": "length_check: if (len < MAX_SIZE)",
    "dataflow_path": "argv[1] → url → buf → strcpy(dest, buf)",
    "risk_level": "medium",  # high/medium/low/safe
    "ast_confidence": 0.7,   # AST 层面的置信度
}
```

**复杂度控制：**
- 仅函数内分析（不跨函数），跨函数依赖关系 LLM 语义补全
- 赋值链追踪仅限直接赋值（a=b; c=a;），不做指针/别名分析
- 三周先覆盖 C + Python，Java 第三周基础覆盖

---

### 2.2 RAG 知识库升级（优先级：高）

**当前问题：**
- 只有 CWE 定义（理论），没有真实漏洞案例
- 检索 query 太粗糙（sink 函数名直接映射关键词）
- 没有利用 BigVul 数据集

**升级方案：三层知识库**

#### 层 1：CWE 定义（保留）
- 现有 `cwe_list.json`，保持
- 补充：增加 CWE 的代码示例（从 Juliet Test Suite 提取）

#### 层 2：BigVul 真实案例（新增，核心）

从 `all_c_cpp_release2.0.csv` 构建：

```
处理流程：
BigVul CSV → 提取 CVE ID + vuln_code + fixed_code + CWE mapping
          → 切分函数
          → 构建 (漏洞代码, 修复代码, CWE, CVE) 四元组
          → Embedding → ChromaDB
```

**ChromaDB Collection 设计：**
```
vuln_knowledge/  (原 cwe_collection)
├── cwe_definitions       — CWE 理论定义（已有，补充示例）
├── bigvul_cases          — BigVul 真实漏洞案例（新增）
│   每个文档：
│   {
│       "id": "CVE-2019-1234_func_1",
│       "document": "Vulnerable: strcpy(dest, src); Fixed: strncpy(dest, src, sizeof(dest));\n"
│                    "CWE-121: Stack-based Buffer Overflow\n"
│                    "The vulnerable code copies user input directly to a fixed-size buffer...",
│       "metadata": {
│           "cve_id": "CVE-2019-1234",
│           "cwe_id": "CWE-121",
│           "language": "c",
│           "vuln_type": "buffer_overflow",
│           "project": "linux_kernel",
│           "has_fix": True
│       }
│   }
└── vuln_patterns         — 通用漏洞模式（手工整理 20-30 条，可选）
```

#### 层 3：动态 Few-shot（新增）

检索时根据切片特征选择最适合的示例：

```python
def get_few_shot(code_slice: dict, retrieved_cases: list, max_examples: int = 2) -> str:
    """从检索结果中构建 few-shot 示例。

    优先选择：
    1. 同语言的案例
    2. 同 CWE 类型的案例
    3. 有修复代码的案例（正例）+ 无漏洞的案例（负例）
    """
    examples = []
    for case in retrieved_cases:
        if case["metadata"]["language"] == code_slice["language"]:
            example = f"""
【Similar Case: {case['metadata']['cve_id']} ({case['metadata']['cwe_id']})】
Vulnerable Code Pattern:
{extract_vuln_pattern(case)}
Fix Applied:
{extract_fix_pattern(case)}
"""
            examples.append(example)
        if len(examples) >= max_examples:
            break
    return "\n---\n".join(examples)
```

**检索器升级：**

```python
# 旧：关键词映射
def _code_to_query(code):
    if "strcpy" in code: return "buffer overflow strcpy"

# 新：综合代码特征 + sink 类型 + 语言
def _code_to_query(slice_info):
    parts = [
        f"{slice_info['language']} vulnerability",
        f"sink: {slice_info.get('sink_category', 'unknown')}",
        f"function: {slice_info.get('sink_type', '')}",
    ]
    if slice_info.get("has_sanitization"):
        parts.append("with input validation")
    if slice_info.get("dataflow_path"):
        parts.append(f"dataflow: {slice_info['dataflow_path'][:80]}")
    return "; ".join(parts)
```

---

### 2.3 LLM Pipeline 升级（优先级：高）

**当前问题：**
- 所有切片一次 Prompt 搞定，不管复杂度
- 没有推理链，容易误判
- 对本地模型（7-16B）没有针对性优化

**升级方案：三阶段推理**

#### Stage 1：快速筛查（低温度，短 Prompt）

目标：过滤明显安全的切片，减少后续 LLM 调用量

```
Prompt：只判断是否有可能存在漏洞，不等定级

条件跳过 Stage 1（直接进入 Stage 2）：
- ast_confidence >= 0.8（静态分析高置信度）
- sanitization_detail 为空（没有缓解措施）
- risk_level == "high"
```

```python
STAGE1_PROMPT = """You are a code security triage specialist. Quickly determine if this code MIGHT contain a security vulnerability.

{code_slice}

Return JSON: {{"suspicious": true/false, "reason": "one sentence"}}

Rules:
- If the code clearly sanitizes input (length check, type casting, parameterized query), return false
- If unsure, return true (err on the side of caution)
- Only return false if you are VERY confident the code is safe
"""
```

#### Stage 2：CoT 深度分析（RAG 增强）

目标：对有嫌疑的切片进行深度漏洞分析

```
Prompt 结构：
1. 角色设定 + 任务说明
2. 静态分析上下文（source、sink、数据流路径、sanitization）
3. RAG 检索案例（相似 CVE/CWE + 修复方案）
4. Few-shot 示例（同语言、同类型的案例）
5. 待分析代码
6. Chain-of-Thought 推理指令
```

```python
STAGE2_PROMPT = """You are a senior code security auditor. Perform a thorough vulnerability analysis.

【Static Analysis Context】
- Language: {language}
- Sink Function: {sink_type} ({sink_category})
- Data Source: {source_var} ({source_type})
- Data Flow: {dataflow_path}
- Sanitization: {sanitization_detail or "None detected"}

【Similar Vulnerability Cases】
{retrieved_cases}

【Few-shot Examples】
{few_shot_examples}

【Code to Analyze】
​```{language}
{code}
```

Think step by step:
1. Trace the data flow from source to sink. Is user input reachable?
2. Check sanitization. Is it sufficient? Can it be bypassed?
3. If the vulnerability is real, what is the impact?
4. What is the CWE classification?
5. What remediation do you recommend?

Output JSON:
{{
  "has_vulnerability": true/false,
  "vulnerability_type": "CWE-XXX",
  "cwe_id": "CWE-XXX",
  "confidence": 0.0-1.0,
  "severity": "HIGH/MEDIUM/LOW/INFO",
  "exploitability": "EASY/MODERATE/DIFFICULT/NONE",
  "impact": "description of potential impact",
  "reasoning_chain": {{
    "step1_dataflow": "...",
    "step2_sanitization": "...",
    "step3_impact": "..."
  }},
  "line_numbers": [int],
  "remediation": "specific fix recommendation",
  "cwe_reference": "URL to CWE definition"
}}
"""
```

#### Stage 3：自检验证

目标：让 LLM 检验自己的判断，降低假阳性

​```python
STAGE3_PROMPT = """Review this vulnerability finding for false positives.

【Finding】
{stage2_result}

【Original Code】
​```{language}
{code}
```

Challenge each conclusion:
1. Is the data source TRULY attacker-controllable? Could it come from a trusted source?
2. Can the sanitization be bypassed? If yes, how specifically?
3. Would this actually cause harm in practice, or is it a theoretical issue?
4. Is the severity assessment accurate? Consider real-world exploitability.

Output JSON:
{{
  "confirmed": true/false,
  "adjusted_confidence": 0.0-1.0,
  "adjusted_severity": "HIGH/MEDIUM/LOW/INFO",
  "false_positive_reason": "if confirmed=false, explain why",
  "refined_description": "updated description if any corrections"
}}
"""
```

**Stage 1 跳过策略（节省推理时间）：**

​```python
def should_skip_stage1(slice_info):
    """满足以下条件直接进入 Stage 2，跳过筛查"""
    if slice_info.get("ast_confidence", 0) >= 0.8:
        return True
    if slice_info.get("risk_level") == "high":
        return True
    if not slice_info.get("has_sanitization"):
        # 没有缓解措施 + sink 是危险函数 = 直接深度分析
        high_risk_sinks = ["system", "eval", "exec", "strcpy", "gets",
                          "pickle.loads", "Runtime.exec", "os.system"]
        if slice_info.get("sink_type") in high_risk_sinks:
            return True
    return False
```

---

### 2.4 SCA 供应链扫描升级

**当前问题：**
- 只解析 `requirements.txt` 和 `setup.py`
- 每次扫描都实时查询 OSV API（慢、有频率限制）

**升级方案：**

1. **离线 CVE 缓存**
   - 首次运行时从 OSV/NVD 拉取常用 Python 包的 CVE
   - 后续扫描走本地缓存（24h 过期）
   - 缓存文件：`data/cache/osv_cache.json`

2. **Java 基础支持（Maven）**
   - 解析 `pom.xml` 提取 `groupId:artifactId:version`
   - OSV API 支持 Maven 生态（`ecosystem: "Maven"`）
   - 第三周做

3. **结果增强**
   - 每个 CVE 附带 CVSS 评分、利用难度、修复版本
   - 输出中标记"是否可被远程利用"

---

### 2.5 评测体系升级

**当前问题：**
- 只在 200 条 BigVul 样本上跑全量对比
- 没有消融实验，无法说明每项改进的贡献
- 没有与传统工具的对比

**升级方案：**

#### 数据集

| 数据集 | 语言 | 规模 | 用途 |
|--------|------|------|------|
| BigVul (全量) | C/C++ | ~500 函数对 | 主评测集 |
| Juliet Test Suite | C/Java | CWE 子集 | Ground Truth 评测 |
| 手工测试集 | Python | ~30 样本 | Python 定性评测 |

#### 对比基线

```python
BASELINES = {
    "codeql": "github/codeql (CLI)",    # C, Java
    "semgrep": "semgrep CLI",           # C, Python, Java
    "bandit": "bandit (Python only)",   # Python
}
```

#### 消融实验设计

```
实验组：
1. Baseline (纯 Prompt，无 RAG，无数据流)     — 对应 VulnRAG-Audit 原版
2. + DataFlow (数据流路径)                    — 加了模块 2.1
3. + RAG     (CWE + BigVul 知识库)            — 加了模块 2.2
4. + MultiStage (三阶段推理)                  — 加了模块 2.3
5. Full System (全部开启)                     — 完整系统

每组输出：TP, FP, FN, TN, Prec, Recall, F1, FPR
```

#### 评测脚本设计

```python
# src/evaluation/ablation.py
class AblationEvaluator:
    def run_ablation(self, test_set, ground_truth):
        configs = [
            {"name": "Baseline",      "rag": False, "dataflow": False, "multistage": False},
            {"name": "+DataFlow",     "rag": False, "dataflow": True,  "multistage": False},
            {"name": "+RAG",          "rag": True,  "dataflow": True,  "multistage": False},
            {"name": "+MultiStage",   "rag": True,  "dataflow": True,  "multistage": True},
        ]
        results = {}
        for cfg in configs:
            predictions = run_scan(test_set, **cfg)
            results[cfg["name"]] = evaluate(predictions, ground_truth)
        return results
```

#### 报告输出

```
消融实验结果表：
┌──────────────┬───────────┬────────┬───────┬────────┐
│ Config       │ Precision │ Recall │ F1    │ FPR    │
├──────────────┼───────────┼────────┼───────┼────────┤
│ Baseline     │ 0.7234    │ 0.6541 │ 0.6870│ 0.2133 │
│ +DataFlow    │ 0.8012    │ 0.6823 │ 0.7370│ 0.1421 │
│ +RAG         │ 0.8456    │ 0.7211 │ 0.7784│ 0.1023 │
│ +MultiStage  │ 0.8712    │ 0.7534 │ 0.8080│ 0.0834 │
├──────────────┼───────────┼────────┼───────┼────────┤
│ CodeQL       │ 0.7890    │ 0.7123 │ 0.7487│ 0.1512 │
│ Semgrep      │ 0.6512    │ 0.8341 │ 0.7313│ 0.3112 │
│ Bandit       │ 0.7012    │ 0.6234 │ 0.6600│ 0.2234 │
└──────────────┴───────────┴────────┴───────┴────────┘
```

---

## 三、项目结构（升级后）

```
D:\project\skill\
├── CLAUDE.md
├── reference-repo/            # 原始 VulnRAG-Audit（只读参考）
├── bigvul_temp/               # BigVul 数据集（只读）
│
├── code-audit/                # 路线二：代码审计（主工作目录）
│   ├── config.yaml            # 统一配置
│   ├── requirements.txt
│   ├── src/
│   │   ├── __init__.py
│   │   ├── main.py            # CLI 入口（修改）
│   │   ├── config.py          # 配置管理（保留原架构）
│   │   │
│   │   ├── scanner/           # 静态分析（全面升级）
│   │   │   ├── __init__.py
│   │   │   ├── code_slicer.py       # AST 切片（升级）
│   │   │   ├── dataflow.py          # 新增：Source→Sink 数据流
│   │   │   ├── sanitization.py      # 新增：Sanitization 识别
│   │   │   ├── sink_registry.py     # 新增：Sink/Source 定义集中管理
│   │   │   └── sca_scanner.py       # SCA 扫描（升级：离线缓存）
│   │   │
│   │   ├── llm/               # LLM 推理（全面升级）
│   │   │   ├── __init__.py
│   │   │   ├── ollama_client.py     # 保留原架构
│   │   │   ├── prompt_builder.py    # 全面重写
│   │   │   ├── parser.py            # 保留，增强容错
│   │   │   ├── few_shot_examples.py # 动态 few-shot 管理
│   │   │   └── stages.py            # 新增：三阶段推理调度
│   │   │
│   │   ├── rag/               # RAG 知识库（大幅升级）
│   │   │   ├── __init__.py
│   │   │   ├── knowledge_base.py    # 知识库管理（升级）
│   │   │   ├── vector_store.py      # ChromaDB 封装（保留）
│   │   │   ├── retriever.py         # 检索器（升级）
│   │   │   └── bigvul_loader.py     # 新增：BigVul 数据导入
│   │   │
│   │   ├── postprocess/       # 后处理（保留+微调）
│   │   │   ├── __init__.py
│   │   │   ├── validator.py
│   │   │   └── cwe_mapper.py
│   │   │
│   │   ├── evaluation/        # 评测（全面升级）
│   │   │   ├── __init__.py
│   │   │   ├── evaluator.py         # 评测器（升级：消融实验）
│   │   │   ├── report_generator.py
│   │   │   ├── visualize.py
│   │   │   └── baselines.py         # 新增：外部工具对比运行
│   │   │
│   │   └── utils/             # 工具类
│   │       ├── __init__.py
│   │       ├── cache.py
│   │       ├── file_utils.py
│   │       └── logger.py
│   │
│   ├── data/
│   │   ├── knowledge_base/
│   │   ├── vector_db/
│   │   ├── cache/
│   │   ├── raw/
│   │   │   └── bigvul/        # BigVul 处理后数据
│   │   └── test_cases/        # 测试用样本
│   │
│   ├── reports/               # 输出报告
│   ├── tests/
│   └── scripts/
│       ├── prepare_bigvul.py        # BigVul 预处理（升级）
│       ├── run_ablation.py          # 新增：消融实验脚本
│       └── compare_baselines.py     # 新增：外部工具对比
│
├── api-security/              # 路线一（第三周）
│   └── (待后续设计)
│
├── shared/                    # 公共模块
│   └── (LLM 调用抽象层等)
│
├── data/                      # 全局测试数据
└── docs/                      # 文档
    └── superpowers/specs/     # 设计文档
```

---

## 四、三周执行计划

### Week 1：静态分析升级 + 知识库建设

| 序号 | 任务 | 产出 | 验证条件 |
|------|------|------|---------|
| 1.1 | 提取 `sink_registry.py` — C/Python sink/source/sanitization 定义 | 集中化的规则文件 | 可独立 import 使用 |
| 1.2 | 实现 `dataflow.py` — Source→Sink 路径追踪 | 函数内数据流分析 | 对 vuln_c_samples 输出数据流路径 |
| 1.3 | 实现 `sanitization.py` — 缓解措施识别 | sanitization 检测 | 能区分 safe_cmd vs vuln_cmd |
| 1.4 | 重构 `code_slicer.py` — 集成 dataflow + sanitization | 升级后的切片器 | 输出带 risk_level 的切片列表 |
| 1.5 | 实现 `bigvul_loader.py` — BigVul CSV 解析 + 导入 ChromaDB | BigVul 案例库 | ChromaDB 可检索到 CVE 案例 |
| 1.6 | 升级 `retriever.py` — 综合特征检索 + 动态 few-shot | 增强检索器 | 返回 CWE + BigVul 混合结果 |

### Week 2：LLM Pipeline + 评测管线

| 序号 | 任务 | 产出 | 验证条件 |
|------|------|------|---------|
| 2.1 | 重写 `prompt_builder.py` — CoT 三阶段 Prompt | 新 Prompt 模板 | 每个 stage 独立可测 |
| 2.2 | 实现 `stages.py` — 三阶段推理调度 | 推理调度器 | 完整跑通 baseline + rag + multistage |
| 2.3 | 实现 `baselines.py` — CodeQL/Semgrep/Bandit 集成 | 外部工具跑分 | 输出对比指标 |
| 2.4 | 实现 `run_ablation.py` — 消融实验 | 消融脚本 | 输出四组实验对比表 |
| 2.5 | 准备评测数据：BigVul 全量 + Juliet 子集 | 评测数据集 | 标注文件 ready |

### Week 3：评测 + 报告 + Java 基础支持

| 序号 | 任务 | 产出 | 验证条件 |
|------|------|------|---------|
| 3.1 | 运行全量评测 + 消融实验 | 评测数据 | F1 优于传统工具基线 |
| 3.2 | Java 基础支持：tree-sitter-java + sink 定义 | Java sink 覆盖 | 能扫描简单 Java 文件 |
| 3.3 | SCA Java 支持：pom.xml 解析 | Maven 依赖扫描 | 能检测 log4j 等经典 CVE |
| 3.4 | 生成评测报告 + 可视化图表 | 报告文档 | HTML 报告完整 |
| 3.5 | 路线一初步调研（API 安全分析） | 调研文档 | 为后续打基础 |

---

## 五、关键技术风险与对策

| 风险 | 影响 | 对策 |
|------|------|------|
| 数据流追踪做不好 | 切片质量没提升 | 降级：不做完整数据流，只做"source 变量是否出现在 sink 参数中"的轻量检查 |
| 本地 LLM 推理质量差 | F1 上不去 | 加大 RAG 投入补偿；多轮投票；尝试 Qwen-Coder 作为备选模型 |
| BigVul 数据质量问题 | 知识库有噪声 | 预处理时过滤：去除无 CWE 映射的条目、代码太短/太长的异常样本 |
| Ollama 推理太慢 | 评测时间不够 | Stage 1 快速筛查大幅减少调用量；并发调用多个 Ollama 实例 |
| 传统工具对比不理想 | 数字难看 | 重点突出消融实验增益，工具对比放在次要位置 |

---

## 六、未覆盖项（明确不做）

- Java 的完整数据流分析（只做 sink 匹配）
- C 项目的 SCA 扫描（C 依赖管理太分散，不投入时间）
- Streamlit Web 界面升级（保持原版可用即可）
- 动态分析（沙箱执行等）
- API 安全分析（路线一，第三周仅做调研）

