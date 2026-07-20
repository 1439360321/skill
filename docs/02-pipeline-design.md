# LLM-First + 静态兜底 — 混合管道优化方案

> 设计目标：静态处理确定性，LLM处理灰色地带
> 避免三个极端：纯静态过拟合、LLM被边缘化、全LLM太慢

---

## 一、管道架构

```
源文件
  │
Layer 0: 静态分析 — 确定性判定
  │
  ├─→ 明显漏洞（sink+无sanitizer+有dataflow）→ 直接标记 VULN
  ├─→ 明显安全（无sink / sink+强sanitizer）→ 直接标记 SAFE
  │
  └─→ 不确定（sink存在，sanitizer部分匹配）→ LLM-First Pipeline
              │
              ▼
Layer 1: 静态线索提取 → 结构化JSON
  输出：{"function":"foo", "sinks":[{"func":"malloc","category":"integer_overflow"}],
         "sources":["count(parameter)"], "sanitizers":["size_guard"],
         "dataflow":"count→malloc", "code_keyline": "buf = malloc(count * size)"}
         │
         ▼
Layer 2: Agent1 "筛查员" — CWE专项Prompt + CoT
  输入：Layer 1 JSON（不含完整源码！防上下文稀释）
  Prompt：每种CWE一个专项prompt，只问一种漏洞类型
  推理：CoT STEP1 → STEP2 → STEP3 → STEP4 → STEP5
  输出：suspicious / safe
         │
         ▼
Layer 3: Agent2 "验证员" — 多轮投票
  输入：JSON + CoT推理链 + 关键代码行 + 源码片段
  temperature: 0.1 / 0.3 / 0.5 各跑一次，3轮投票
  输出：confirmed_vuln / false_positive / uncertain
         │
         ▼
Layer 4: Agent3 "证据员"
  输入：完整源码 + Agent2结论
  输出：具体行号 + CWE引用 + 修复建议
```

## 二、信息流控制（防上下文稀释）

源码逐层递进，不在早期层级出现：

| 层 | ~大小 | 内容 |
|----|:----:|------|
| Layer 0→1 | 1500字符 | 完整源码（仅此层解析） |
| Layer 1→2 | 300字符 | 结构化JSON（无源码） |
| Layer 2→3 | 500字符 | JSON + CoT推理链 |
| Layer 3→4 | 800字符 | JSON + 关键代码行 + 源码片断 |
| Layer 4 | 2000字符 | 完整源码（仅此层看源码） |

## 三、CWE专项Prompt

为5个主要CWE各写一套prompt：buffer_overflow, command_injection, code_injection, sql_injection, path_traversal。每个切片只对匹配的CWE执行对应prompt。

## 四、静态确定性标准

```python
# 直接通过，不走LLM
risk=="high" + 无sanitizer + 有dataflow → "vuln"（明显漏洞）
risk=="low" → "safe"（明显安全）

# 送LLM
risk=="medium" / sanitizer部分匹配 / dataflow不确定 → "uncertain"
```

## 五、评测脚本（5个独立脚本，各管各的）

| 脚本 | 功能 | LLM? | 命令 |
|------|------|:--:|------|
| `scripts/eval_static.py` | 纯静态分析评测 | 无 | `python scripts/eval_static.py` |
| `scripts/eval_llm_self.py` | LLM-First 自建集 | GLM | `python scripts/eval_llm_self.py` |
| `scripts/eval_llm_bigvul.py` | LLM-First BigVul | GLM | `python scripts/eval_llm_bigvul.py` |
| `scripts/eval_ablation.py` | 消融：逐步加模块 | GLM | `python scripts/eval_ablation.py` |
| `scripts/eval_compare.py` | 汇总所有结果到一张表 | 无 | `python scripts/eval_compare.py` |

每个脚本跑完自动存 `reports/` 下对应 JSON，`eval_compare.py` 读所有 JSON 输出总表。

## 六、评测对比

| 方案 | 自建集F1 | BigVul F1 |
|------|:------:|:------:|
| 纯静态 | 0.9062 | 0.4828 |
| 旧LLM(静态为主) | 0.8923 | 0.4444 |
| **LLM-First新方案** | **？** | **？** |

消融实验顺序：纯静态 → +CWE专项 → +CoT → +投票 → +静态兜底(完整管道)
