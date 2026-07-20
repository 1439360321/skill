# LLM 漏洞检测管道 — 调试记录与交接文档

## 项目概述

LLM 辅助代码漏洞检测管道（"LLM-First" 架构），结合静态分析（sink registry + CodeQL + Semgrep）和 LLM 进行多阶段漏洞判定。

## 当前管道架构（v3 — IRIS 简化版）

```
Layer 0: static_decision → vuln/safe 确定性判断，uncertain 进入 LLM
Layer 1: extract_structured_context → 结构化 JSON 上下文
Layer 2: Agent1 Screener → CWE 专项 CoT 筛查
Layer 3: Agent2 Verifier → IRIS 风格单次 CWE 对照验证 (temp=0.1, max_tokens=1024)
Layer 4: Agent3 Evidence → 漏洞行号 + CWE 编号 + 修复建议
```

LLM 调用次数：每样本 2-3 次（agent1 + agent2 + agent3），原始为 5+ 次。

## 已发现的 Bug 及修复

### Bug 1：代码截断（CRITICAL，影响 100% BigVul 样本）
- **原因**：`eval_one.py` 中 `sl["code"] = code` 将 CodeSlicer 提取的函数代码（~200字符）覆盖为完整文件原始代码（~3000字符）。`_extract_keyline` 取 `code[:1500]` 时，大文件的前 1500 字符全是许可证头、include、注释，漏洞代码在截断点之后。
- **修复**：改为 `sl["_file_code"] = code`，保留 `sl["code"]` 中的函数代码。
- **涉及文件**：`eval_one.py` L123/163/214/258，`eval_overnight.py` L49/112/249

### Bug 2：模块 docstring 未闭合
- **原因**：编辑 docstring 时删除了结尾的 `"""`，导致 Python 把整个文件当成一个未闭合字符串。
- **修复**：添加缺失的 `"""`。

### Bug 3：分块逻辑用错行号
- **原因**：`detect()` 中的 FuncVul 分块逻辑使用 `slice_data.get("line_start")` 作为 sink 位置进行中心提取，但 `line_start` 是**函数的起始行号**，不是 sink 所在行。对于长函数，LLM 只看到函数签名附近 ±15 行，完全丢失漏洞代码。
- **修复**：删除分块逻辑，统一使用 `_extract_keyline` 的简单窗口（`code[:2000]`）。

### Bug 4：code_patterns 注入写了 sl["code"] 而非 sl["_file_code"]
- **原因**：CodeQL/Semgrep 结果注入时覆盖了 CodeSlicer 的函数代码。
- **修复**：同上，使用 `_file_code`。

## 管道演化与关键结果

以下数据均为 BigVul 数据集（52 样本，40 vuln / 12 safe），A 阶段永远是 0.6761（静态基线）。

### v1：原始多温度投票 + exploit 验证

| 阶段 | F1 | TP | Recall | 问题 |
|------|-----|-----|--------|------|
| B (agent1 only) | 0.5806 | 18 | 0.45 | agent1 杀 6 TP |
| C (完整管道) | 0.3846 | 10 | 0.25 | 3 温度投票 + exploit 再杀 8 TP |

管道配置：
- Agent2：3 温度投票（0.0/0.3/0.7），≥2/3 判 vuln，2/3 判 safe 则标 FP
- VERIFIER_PROMPT：要求构造 exploit，"写不出 exploit = safe"（SAST-Genius 风格）
- 5+ 次 LLM 调用/样本

### v2：关闭 exploit 验证（`--no-exploit`）

| 阶段 | F1 | TP | Recall |
|------|-----|-----|--------|
| C | 0.5000 | 14 | 0.35 |

关闭 exploit 验证后 C 从 0.38→0.50，证实 exploit 构造是 TP 杀手。

### v3：IRIS 简化管道（当前版本）

改动：
- 删除 3 温度投票 → 单次 IRIS 风格 CWE 对照验证（temp=0.1）
- 删除 exploit 构造 prompt → CWE 定义对照
- max_tokens 2048→1024
- ±10→±5 行代码窗口
- LLM 调用 -40%

| 阶段 | F1 | TP | Recall |
|------|-----|-----|--------|
| B | **0.6032** | **19** | **0.475** |
| C | **0.5424** | **16** | **0.40** |

**最优配置**：B 阶段 `code[:1500]` + C 阶段 `code[:2000]` + IRIS 简化管道。

### v3 上限测试（LLM 全挂，全部标 vuln）

GLM API 限流导致所有 agent1 调用返回 429，意外测得管道理论上界：

| 阶段 | F1 | TP | FP | Recall |
|------|-----|-----|-----|--------|
| C (全部标 vuln) | **0.8046** | **35** | **12** | **0.875** |

**关键结论**：不经过 LLM，Recall 可达 0.875。LLM 是瓶颈。

## 关键发现

### 1. LLM 管道层层杀 TP，不增 TP

```
A(static) = 24 TP
  → agent1 筛查: -5~6 TP
  → agent2 验证: -3~8 TP  
  → C = 10~19 TP
```

**LLM 的价值仅在于 FP 削减，不会发现新的 TP（对当前 GLM-4.6v 而言）。**

### 2. 代码窗口大小的反直觉结果

| B 阶段窗口 | B F1 | 说明 |
|------------|------|------|
| `code[:1500]` | 0.60 | 最佳 |
| `code[:2000]` | 0.47 | 噪声增加 |
| `code[:3000]` | 0.42 | 噪声过多 |
| 智能提取（head+sink） | 0.52 | 丢上下文 |
| 纯 sink 中心 | 0.40 | 丢函数头 |

**结论**：函数开头（签名+声明+早期逻辑）是 LLM 判断漏洞最重要的上下文。加代码量≠加信号，反而引入噪声让 LLM 更保守。

### 3. 多阶段投票是双刃剑

3 温度投票 + ≥2/3 共识 = 过度保守。IRIS/SAST-Genius 论文都是单次 LLM 调用，不做投票。

### 4. SAST-Genius exploit 构造不适合通用 LLM

"写不出 exploit 就说 safe" 这个策略来自 SAST-Genius，但他们用的是 **fine-tuned Llama 3 8B**。通用 GLM-4.6v 无法可靠构造 exploit，导致大量 TP 被杀。

### 5. GLM-4.6v 的天花板

即使最优配置，LLM 管道也只能把 F1 从 0.68（纯静态）降到 0.54。LLM 在漏洞检测任务上天然保守，倾向判 "safe"。

## 数据集状态

| 数据集 | 位置 | 语言 | 状态 |
|--------|------|------|------|
| self-test | `data/test_set.json` | C+Python | 虚高（F1>0.9），不建议验证用 |
| BigVul | `data/bigvul_test_set.json` | C | 可用，52 样本 |
| Juliet | `data/juliet_test_set.json` | C | 已下载，未充分测试 |
| D2A | `data/d2a_test_set.json` | C | 已下载，未充分测试 |
| PrimeVul | `data/primevul_test.csv` | C/C++ | 极高难度（论文 F1=3%），LLM 几乎无法检测 |
| Devign | — | C | 下载失败（HF 旧格式），跳过 |

## 静态工具对比

| 工具 | 语言 | BigVul F1 | 适用性 |
|------|------|-----------|--------|
| Sink Registry | C/Python | **0.73** | 最佳，60+ 模式 |
| CodeQL | C | ~0.00 | 需要编译环境（`--build-mode=none` 只能做 AST 级匹配） |
| Semgrep | Python | — | C 规则极少（仅 `gets()` 等），适合 Python/Java |

**结论**：对 C 代码，sink registry 是最有效的静态信号源。CodeQL 和 Semgrep 在不编译场景下贡献近乎为零。

## 论文借鉴与实验结果

| 论文 | 借鉴点 | 实验结果 |
|------|--------|----------|
| **IRIS** (ICLR 2025) | 单次 temp=0.1 验证、±5 行上下文、max_tokens=1024 | ✅ 有效，C 从 0.38→0.54 |
| **FuncVul** (ESORICS 2025) | 代码分块策略 | ❌ 不适合（基于 diff，非函数大小分块） |
| **SAST-Genius** (IEEE S&P 2025) | exploit 构造 FP 过滤 | ❌ 无效（需 fine-tuned 模型，通用 LLM 导致 TP 被杀） |
| **Wagner et al.** | 多温度投票 | ❌ 已移除（过度保守） |

## 当前代码状态

- `src/llm/llm_first_detector.py`：v3 IRIS 简化管道，`_extract_keyline` 回退到 `code[:2000]`
- `scripts/eval_one.py`：B 阶段 `code[:1500]`，C 阶段 `detector.detect()`（`code[:2000]`）
- `src/scanner/codeql_runner.py`：CodeQL 批量运行器，需要 CodeQL CLI
- `src/scanner/semgrep_runner.py`：Semgrep 批量运行器
- `src/scanner/code_slicer.py`：无 sink 函数也生成切片（`sink_category: "generic"`）

### 运行方式

```bash
# 单数据集评估
python scripts/eval_one.py bigvul

# 控制变量（feature flags 通过环境变量传递）
python scripts/eval_one.py bigvul --no-iris
python scripts/eval_one.py bigvul --no-chunk
```

## 建议

### 短期（高优先级）

1. **换模型**：GLM-4.6v 在漏洞检测上的保守倾向是根本瓶颈。试 DeepSeek V4 或更强的模型。当前代码已适配 OpenAI 兼容 API（`shared.llm.openai_client`），改 `config.yaml` 即可切换。

2. **确认 v3 基线**：API 额度恢复后，用当前代码跑一次 BigVul，确认 B≈0.60、C≈0.54。

3. **跑完整对比**：`python scripts/eval_benchmarks.py`（6 数据集 × 工具 × 消融），但需要先确认单个数据集能跑通。

### 中期

4. **提高 agent1 的召回率**：当前 agent1 是最大 TP 杀手（-5~6 TP）。可以尝试：
   - 在 prompt 中强调 "when in doubt, flag as suspicious"
   - 降低 suspicious 判定阈值
   - 去掉 agent1 直接进 agent2（参考 SAST-Genius 的单次调用模式）

5. **让 CodeQL 真正工作**：`--build-mode=none` 只能跑结构查询。如果能配置编译环境（`codeql database create --build-mode=autobuild`），CodeQL 能做完整数据流分析，IRIS 论文的 ±5 行窗口才能真正发挥作用。

6. **跑控制变量实验**：分别关闭 IRIS/FuncVul 改进，量化每个改进的独立贡献。

### 长期

7. **尝试 fine-tuned 模型**：SAST-Genius 的核心优势来自 fine-tuned Llama 3 8B。如果有条件微调，可以复现其 exploit 构造方案。

8. **扩展 Semgrep 到 Python 数据集**：当前 Semgrep 在 C 上无作用，但对 Python（self-test Python 子集）可能有显著提升。

### 已知陷阱

- **不要用 self-test 验证效果**——这个测试集已经过拟合（F1>0.9），没有区分度。
- **`code[:1500]` 不是 bug，是经验最优值**——不要"优化"成更大的窗口。
- **多阶段管道 = 多阶段 TP 损失**——每加一层验证，先想清楚它能不能真正区分 TP/FP。
- **论文参数不能照搬**——IRIS 用 CodeQL 全编译 + Java，FuncVul 用 diff 分块 + fine-tuned GraphCodeBERT，场景不同。
- **GLM API 有限流（429）**——跑全量评估时控制并发，最好加 retry/backoff 逻辑。
