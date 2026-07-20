# 项目交付总结 — 基于大语言模型的应用安全审计技术

> 三人团队 · 三周（2026-07-07 起）· 先路线二（代码审计），后路线一（API 安全分析）

---

## 一、项目框架总览

```
┌─────────────────────────────────────────────────────────────┐
│                  Streamlit Web 界面                         │
│              (streamlit_app.py — 双路线入口)               │
├──────────────────────────┬──────────────────────────────────┤
│   路线二：代码安全审计    │     路线一：API 安全分析          │
│   (code-audit/)          │     (api_security/)              │
│                          │                                  │
│   输入：源代码文件         │   输入：HAR/JSON/Burp 流量日志    │
│   检测：sink匹配+数据流    │   检测：序列/参数/访问异常        │
│        +sanitization     │        + LLM 行为分析            │
│        +LLM 语义审查      │                                  │
│   输出：漏洞报告+评测指标  │   输出：风险聚合报告              │
├──────────────────────────┴──────────────────────────────────┤
│                    共享层 (shared/)                          │
│              Ollama LLM Client + 公共工具                    │
└─────────────────────────────────────────────────────────────┘
```

### 设计理念

**核心问题**：如何用 LLM 做应用安全审计？

**答案**：LLM + 静态分析互补。静态分析处理有明确规则的安全漏洞（sink 匹配 + sanitization 检测），LLM 处理需要语义理解的逻辑漏洞（手动循环、空指针、off-by-one）。

### 关键设计决策

1. **静态分析优先，LLM 补充** — 大多数漏洞（strcpy、system、eval）有明确的函数调用特征，静态分析准确且快速。LLM 只在静态分析完全盲区才介入。

2. **Sanitization 检测是 FP 杀手** — 不是所有 sink 调用都是漏洞。安全代码会做长度检查、参数化查询、shell 转义等。正确识别这些安全模式是 Precision 从 0.60 提升到 0.83 的关键。

3. **小 LLM 的正确角色** — deepseek-r1:8b 不适合做高精度判断（对安全代码过度推理），但它能发现静态分析完全看不到的逻辑 bug（手动循环越界、off-by-one）。

---

## 二、路线二：代码安全审计

### 执行流程

```
源文件 (C/Python/Java)
    │
    ├── tree-sitter AST 解析
    │
    ├── 函数提取 (function_definition → func_node)
    │
    ├── Sink 匹配 (sink_registry: 120+ 危险函数)
    │   ├── 有匹配 ──→ 数据流追踪 (Source→Sink 路径)
    │   │              ├── Sanitization 检测 (正则匹配安全模式)
    │   │              ├── 风险评级 (high/medium/low)
    │   │              └── 输出: 漏洞切片 + 置信度
    │   │
    │   └── 无匹配 ──→ LLM 语义审查 (semantic_review.py)
    │                   ├── 逻辑漏洞检测 (手动循环/空指针/off-by-one)
    │                   └── 输出: 漏洞发现 (confidence >= 0.85)
    │
    └── CWE 映射 → 结果验证 → 报告生成 (CLI/JSON/HTML)
```

### 模块架构

| 层 | 模块 | 职责 |
|----|------|------|
| **扫描** | `sink_registry.py` | 120+ sink / 40+ source / 55+ sanitization 规则 (C/Python/Java) |
| | `dataflow.py` | 函数内 Source→Sink 数据流追踪 |
| | `sanitization.py` | 正则匹配安全模式（长度检查/参数化查询/shell转义等） |
| | `code_slicer.py` | 集成 dataflow+sanitization，风险评级 |
| | `sca_scanner.py` | 供应链扫描 (requirements.txt + pom.xml + OSV API) |
| **LLM** | `ollama_client.py` | Ollama REST API 客户端 |
| | `semantic_review.py` | **新**：针对性 LLM 语义审查（仅用于静态分析盲区） |
| | `stages.py` | 旧三阶段 LLM 管线（保留，非默认） |
| | `prompt_builder.py` | Prompt 模板 + RAG 上下文注入 |
| | `parser.py` | LLM 输出解析（R1 `<think>` 过滤 + JSON 容错） |
| **RAG** | `bigvul_loader.py` | BigVul 数据集 → ChromaDB |
| | `retriever.py` | 混合检索 (CWE + BigVul 案例) |
| | `vector_store.py` | ChromaDB 懒加载 + 优雅降级 |
| **后处理** | `validator.py` | 置信度过滤 + 结果规范化 |
| | `cwe_mapper.py` | 70+ CWE 映射表 |
| **评测** | `evaluator.py` | Precision/Recall/F1/FPR |
| | `visualize.py` | 消融实验柱状图 + 外部工具雷达图 |
| | `report_generator.py` | CLI 报告 + JSON + 自包含 HTML |

### 检测覆盖

| 类别 | CWE | C 示例 | Python 示例 |
|------|-----|--------|------------|
| 缓冲区溢出 | CWE-119/120/121/122 | strcpy, gets, memcpy | — |
| 命令注入 | CWE-77/78 | system, popen | os.system, subprocess.Popen(shell=True) |
| SQL 注入 | CWE-89 | mysql_query | cursor.execute(f"SELECT...") |
| 代码注入 | CWE-94/95 | — | eval, exec |
| 格式字符串 | CWE-134 | printf(user_input) | — |
| 路径遍历 | CWE-22 | fopen(user_path) | open(user_path) |
| 整数溢出 | CWE-190 | malloc(n * size) without check | — |
| 反序列化 | CWE-502 | — | pickle.load, yaml.load |
| 内存损坏 | CWE-415/416 | free, double-free, use-after-free | — |
| 凭证硬编码 | CWE-798 | mysql_connect(password) | psycopg2.connect(password=) |
| 空指针解引用 | CWE-476 | *ptr without null check | — |
| 越界读取 | CWE-125 | manual while loop | — |
| 越界写入 | CWE-787 | off-by-one for loop | — |
| **逻辑漏洞** | CWE-690/826 | **LLM 检测** | **LLM 检测** |

### 最终评测（59 样本）

```
Static Only (slicer + sanitization):
  Precision=0.8286  Recall=0.9062  F1=0.8657  FPR=0.2308
  TP=29  FP=6  FN=3  TN=20

Static + LLM Semantic Review:
  Precision=0.8205  Recall=1.0000  F1=0.9014  FPR=0.2692
  TP=32  FP=7  FN=0  TN=19

LLM 贡献: +3 TP (无sink逻辑漏洞), Recall +9.4%, F1 +3.6%, 零漏报
代价: +1 FP (safe_null_01.c R1幻觉)
```

---

## 三、路线一：API 安全分析

### 执行流程

```
流量文件 (HAR / JSON-log / Burp XML)
    │
    ├── 流量解析 (parser.py)
    │   ├── 请求结构化 (method, path, params, body, headers)
    │   ├── 路径参数化 (/users/123 → /users/{id})
    │   └── 用户提取 (Bearer token / cookie / header)
    │
    ├── Session 构建 (session.py)
    │   └── 按用户分组 + 时间窗口
    │
    ├── 三个检测器
    │   ├── SequenceDetector (sequence.py)
    │   │   ├── 启发式预过滤 (_is_suspicious)
    │   │   └── LLM 深度分析 (枚举/提权/异常模式)
    │   │
    │   ├── ParameterDetector (parameter.py)
    │   │   ├── 自动发现所有数字参数
    │   │   └── 顺序 ID 检测 (ratio > threshold)
    │   │
    │   └── AccessDetector (access.py)
    │       ├── 跨用户资源重叠分析
    │       ├── 全用户配对 (最多5用户, 3对LLM)
    │       └── 响应体字段对比 (IDOR/BOLA)
    │
    └── RiskAggregator (aggregator.py)
        ├── 去重 (endpoint, anomaly_type)
        └── 报告生成 (JSON + HTML)
```

### 模块架构

| 层 | 模块 | 职责 |
|----|------|------|
| **流量** | `parser.py` | 3 格式解析 (HAR/JSON/Burp XML) + 路径参数化 + 用户提取 |
| | `session.py` | 时间窗口 + 用户分组 session 构建 |
| **检测** | `sequence.py` | 会话序列异常 (枚举/提权) + 启发式预过滤 |
| | `parameter.py` | 参数遍历检测 (顺序 ID 扫描) |
| | `access.py` | IDOR/BOLA 越权检测 + 响应体对比 |
| | `aggregator.py` | 风险聚合 + 去重 + 报告生成 |
| **LLM** | `prompts.py` | 4 套专用 Prompt + session/param/access 摘要函数 |

### 检测类型

| 类型 | 检测器 | 方法 |
|------|--------|------|
| 资源枚举 | Sequence + Parameter | LLM 会话分析 + 顺序 ID 检测 |
| 权限提升 | Sequence | LLM 操作模式分析 |
| IDOR/BOLA | Access | 跨用户资源重叠 + LLM 响应体对比 |
| 参数遍历 | Parameter | 自动发现 + 启发式 ratio 阈值 |
| 信息泄露 | Access | 响应体字段提取 + 跨用户对比 |

### 当前状态

- 10/10 单元测试通过
- 3 种流量格式支持
- LLM + 启发式双模运行
- 7 项功能优化已实施
- **待完成**：用真实流量数据跑 LLM 评测闭环

---

## 四、技术栈

| 组件 | 方案 |
|------|------|
| LLM | Ollama + deepseek-r1:8b（本地） |
| AST | tree-sitter (C, Python, Java) |
| RAG | ChromaDB + sentence-transformers (all-MiniLM-L6-v2) |
| SCA | OSV.dev API + 24h 缓存 |
| 评测 | Precision/Recall/F1/FPR + matplotlib |
| Web | Streamlit |
| 数据集 | BigVul, 自建 59 样本标注集 |

---

## 五、项目结构

```
D:\project\skill\
├── CLAUDE.md                     # 项目说明
├── streamlit_app.py              # 统一 Web 界面
│
├── code-audit/                   # 路线二：代码审计
│   ├── config.yaml
│   ├── src/
│   │   ├── main.py               # CLI 入口
│   │   ├── scanner/              # sink_registry / dataflow / sanitization / code_slicer / sca_scanner
│   │   ├── llm/                  # ollama_client / prompt_builder / stages / parser / semantic_review
│   │   ├── rag/                  # vector_store / knowledge_base / retriever / bigvul_loader
│   │   ├── postprocess/          # validator / cwe_mapper
│   │   ├── evaluation/           # evaluator / visualize / report_generator / baselines
│   │   └── utils/                # logger / cache / file_utils
│   ├── scripts/                  # prepare_bigvul.py / run_ablation.py / evaluate_llm.py
│   ├── tests/                    # 16 个测试用例
│   ├── examples/                 # 49 个 safe/vuln C + Python 样本
│   └── data/                     # test_set.json / knowledge_base
│
├── api_security/                 # 路线一：API 安全分析
│   ├── config.yaml
│   ├── src/
│   │   ├── main.py               # CLI 入口
│   │   ├── traffic/              # parser / session
│   │   ├── detector/             # sequence / parameter / access / aggregator
│   │   ├── llm/                  # prompts
│   │   └── eval/                 # 评测框架
│   ├── tests/                    # 10 个测试用例
│   └── data/                     # sample_idor.json / sample_traffic.json
│
├── shared/                       # 公共模块
│   └── llm/                      # base_client / ollama_client
│
├── docs/                         # 文档
│   ├── CHANGELOG.md              # 完整优化变更记录
│   ├── SUMMARY.md                # 本文件
│   └── superpowers/specs/        # 设计文档
│
└── reference-repo/               # VulnRAG-Audit 参考（只读）
```

---

## 六、快速开始

```bash
# 安装依赖
pip install -r code-audit/requirements.txt

# 确保 Ollama 运行
ollama serve

# 路线二：代码审计
cd code-audit
python -m src.main examples --mode baseline           # 纯静态扫描
python -m src.main examples --mode rag --json --html  # RAG 增强
python scripts/evaluate_llm.py examples --ground-truth data/test_set.json  # LLM 评测

# 路线一：API 安全分析
cd api_security
python -m src.main data/sample_idor.json              # LLM 模式
python -m src.main data/sample_traffic.json --no-llm  # 启发式模式

# Web 界面
streamlit run streamlit_app.py
```

## 七、已知局限

### 路线二
- 数据流追踪仅限函数内（不跨函数）
- Java 仅基础 sink 匹配（无数据流追踪）
- 3 类逻辑漏洞（手动循环、空指针、off-by-one）依赖 LLM，无 LLM 时无法检测
- deepseek-r1:8b 对安全代码有 ~15% 幻觉率（1/6 无 sink 文件被误报）
- LLM 推理速度慢（~10s/文件），不适合大规模扫描

### 路线一
- 尚未用真实流量数据跑过完整 LLM + 评测闭环
- deepseek-r1:8b 对 API 行为分析的质量未量化验证
- 启发式阈值需要根据实际数据调优
