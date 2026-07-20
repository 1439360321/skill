# 基于大语言模型的应用安全审计技术

课程大作业，包含两个子路线：

- **路线一：API安全分析**（`api_security/`）—— 基于LLM的API流量异常检测，覆盖IDOR、参数遍历、序列攻击
- **路线二：代码漏洞审计**（`code-audit/`）—— LLM-First混合管道，静态分析+LLM多智能体协同检测C/C++/Python漏洞

## 评测结果（路线二）

| 数据集 | 方法 | F1 | Precision | Recall | FPR |
|--------|------|:--:|:---------:|:------:|:---:|
| 自建集 (59) | 纯静态 | 0.906 | 0.906 | 0.906 | 0.094 |
| 自建集 (59) | **LLM-First** | **0.921** | 0.936 | 0.906 | 0.063 |
| BigVul (25) | 纯静态 | 0.483 | 0.700 | 0.368 | 0.500 |
| BigVul (25) | **LLM-First** | **0.743** | 0.813 | 0.684 | 0.500 |

## 架构

```
输入代码
  ├── Layer 0: static_decision() — 确定性判定
  ├── Layer 1: 结构化JSON线索提取
  ├── Layer 2: Agent1 筛查员 — CWE专项CoT Prompt
  ├── Layer 3: Agent2 验证员 — 多温度投票
  └── Layer 4: Agent3 证据收集 — 行号+CWE+修复建议
```

## 快速开始

### 环境要求

- Python 3.10+
- GLM API Key（ZhipuAI）

### 配置

```bash
cp .env.example .env
# 编辑 .env 填入 GLM_API_KEY
```

### 运行

```bash
cd code-audit

# API测试
python test_api.py

# 自建集评测
python scripts/eval_llm_self.py

# BigVul独立集评测
python scripts/eval_llm_bigvul.py

# 消融实验
python scripts/eval_ablation.py

# 汇总对比
python scripts/eval_compare.py
```

### 模型切换

编辑 `code-audit/config.yaml`：

```yaml
llm:
  provider: "openai"
  model: "glm-4.6v"
  api_key: "${GLM_API_KEY}"
  base_url: "https://open.bigmodel.cn/api/paas/v4"
```

## 项目结构

```
├── .env.example              # API Key模板
├── code-audit/
│   ├── config.yaml           # LLM配置
│   ├── src/
│   │   ├── llm/
│   │   │   └── llm_first_detector.py  # LLM-First核心管道
│   │   ├── scanner/          # 静态分析（sink检测、数据流、切片）
│   │   └── evaluation/       # 评测引擎
│   ├── scripts/
│   │   ├── eval_llm_self.py
│   │   ├── eval_llm_bigvul.py
│   │   ├── eval_ablation.py
│   │   └── eval_compare.py
│   └── data/
│       └── test_set.json
├── api_security/
│   └── src/
│       ├── detector/
│       ├── traffic/
│       └── eval/
└── shared/
    └── llm/
        └── openai_client.py
```

## 详细文档

- [CHANGES.md](CHANGES.md) — 完整修改记录、消融分析、提升归因
