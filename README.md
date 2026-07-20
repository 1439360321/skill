# 基于大语言模型的代码漏洞审计

课程大作业。零样本 LLM + 多 Agent 协同 + 结构化六类审计清单。

## 最终成绩

| 数据集 | F1 | Precision | Recall | FPR | 样本 |
|--------|:---:|:---------:|:------:|:---:|:---:|
| PrimeVul | **0.77** | 0.78 | 0.75 | 0.21 | 200 分层 |
| BigVul (clean) | **0.67** | 0.62 | 0.74 | 0.46 | 200 分层 |
| PrimeVul 有 sink 子集 | **0.88** | 1.00 | 0.79 | — | 19 |
| PrimeVul 无 sink 子集 | **0.74** | 0.74 | 0.74 | — | 181 |

零样本（无微调），DeepSeek V4 Flash，200 样本分层采样。对比学术界：StarCoder2 7B (F1=0.03)、CodeBERT 微调 (F1=0.21)、LLMxCPG (F1=0.62-0.68，需 CPG 输入)。

## 消融实验

| 配置 | F1 | P | R |
|------|:---:|:---:|:---:|
| V3 基线（静态拦截 + 截断） | 0.18 | 0.29 | 0.13 |
| Fair 单次（完整代码 + confirm_it） | 0.67 | 0.57 | 0.80 |
| V4 无 RAG | 0.70 | 0.54 | 1.00 |
| **V4 完整** | **0.77** | **0.78** | **0.75** |

三层 Agent 架构 + confirm_it 仲裁 + checklist 六类审计，无 RAG 贡献。

## 架构

```
V4: Tool-Aware Chain + Checklist

有 sink 路径                      无 sink 路径
A1: 工具报告 → 窗口策略            A1: 工具报告 → full 窗口
A2: confirm_it 验证 sink           A2: checklist 六类专项审计
A3: checklist 补漏盲区
    ↓                                  ↓
后处理: ConflictArbitrator + ConfidenceCalibrator + OutputQualityChecker
```

### checklist 六类审计

| 类别 | 检测内容 |
|------|---------|
| MEMORY | UAF / 双重释放 / 内存泄漏 |
| INTEGER | 溢出 / 截断 / 符号转换 |
| BOUNDARY | 越界 / off-by-one |
| CONCURRENCY | 竞态 / TOCTOU / 死锁 |
| ERROR PATHS | 空指针 / 资源泄漏 / 返回值忽略 |
| LOGIC | 条件错误 / 缺分支 / 索引越界 |

## 第三方库 / 供应链分析

独立 SCA 模块，查询 OSV.dev API 检测依赖库已知漏洞：

```bash
cd code-audit
python -m src.main <project_dir> --sca
```

支持 `requirements.txt`（PyPI）和 `pom.xml`（Maven），结果带 24h 本地缓存。

## 快速开始

### 环境

```bash
pip install -r code-audit/requirements.txt
cp .env.example .env  # 填入 DEEPSEEK_API_KEY 和 SILICONFLOW_API_KEY
```

### 评测

```bash
cd code-audit

# 200 样本 PrimeVul 评测（分层 100v+100s）
python scripts/eval_200_primevul.py

# 200 样本 BigVul 评测
python scripts/eval_200_bigvul.py

# 消融实验
python scripts/ablation_30.py

# 快速测试（30 样本）
python scripts/quick_sink_test.py
```

### LLM 提供商

编辑 `code-audit/config.yaml`：

```yaml
llm:
  provider: "openai"
  api_key: "${DEEPSEEK_API_KEY}"
  base_url: "https://api.deepseek.com"
  model: "deepseek-chat"
```

## 项目结构

```
├── code-audit/
│   ├── src/
│   │   ├── llm/pipeline/
│   │   │   ├── orchestrator.py     # 管道编排 + 预设
│   │   │   ├── llm_strategy.py     # 三级 Agent + 所有 prompt
│   │   │   ├── static_decision.py  # 静态决策层
│   │   │   ├── code_window.py      # 动态窗口
│   │   │   └── post_processor.py   # 仲裁+校准+质量检查
│   │   ├── scanner/
│   │   │   ├── code_slicer.py      # AST sink 检测 + 数据流
│   │   │   ├── tool_aggregator.py  # 多工具结果聚合
│   │   │   ├── codeql_runner.py    # CodeQL 批量运行
│   │   │   └── semgrep_runner.py   # Semgrep 批量运行
│   │   └── rag/
│   │       └── vector_store.py     # ChromaDB + bge-m3 嵌入
│   ├── scripts/                    # 评测脚本
│   ├── data/
│   │   ├── bigvul_clean_200.json   # BigVul 干净测试集
│   │   └── bigvul_test_set.json   # BigVul 旧测试集
│   └── deprecated/                 # 废弃代码（备查）
├── shared/                         # LLM 客户端
├── docs/                           # 完整文档（12 篇）
└── .env.example
```

## 文档索引

| 文档 | 内容 |
|------|------|
| [10-v4-evaluation.md](docs/10-v4-evaluation.md) | V4 最终评测结果与方法 |
| [11-project-journey.md](docs/11-project-journey.md) | 完整探索历程（6 阶段） |
| [07-architecture-evolution.md](docs/07-architecture-evolution.md) | 架构演进记录 |
| [06-phase2-debug-log.md](docs/06-phase2-debug-log.md) | 早期调试记录 |
| [12-usage-guide.md](docs/12-usage-guide.md) | 详细使用指南 |
