# V4 管道评测记录（最终版）

**日期**: 2026-07-20
**模型**: DeepSeek V4 Flash (`deepseek-chat`)
**管道**: V4 preset (Tool-Aware Chain)

---

## 1. 最终成绩

### 200 样本分层评测

| | PrimeVul (200) | BigVul clean (200) |
|---|------|------|
| **F1** | **0.77** | **0.67** |
| Precision | 0.78 | 0.62 |
| Recall | 0.75 | 0.74 |
| FPR | 0.21 | 0.46 |
| 有 sink F1 | 0.88 (19个) | 0.75 (45个) |
| 无 sink F1 | 0.74 (181个) | 0.64 (155个) |
| LLM 调用 | 420 (2.1/样本) | 447 (2.2/样本) |
| 耗时 | 1052s | 1615s |

### 消融实验（30 样本）

| 配置 | F1 | P | R | 说明 |
|------|-----|---|---|------|
| V3 单次调用 (static 拦截+截断) | 0.18 | 0.29 | 0.13 | 基线——最弱 |
| Fair 单次 (完整代码+confirm_it) | 0.67 | 0.57 | 0.80 | 去掉拦截和截断 |
| V4 完整 | 0.70 | 0.54 | 1.00 | 三层 Agent |
| V4 无 RAG | 0.70 | 0.54 | 1.00 | RAG 无贡献 |

---

## 2. 最终管道配置

```yaml
static_decision:
  no_sink: "uncertain"
  low_risk_sink: "uncertain"
  sanitizer_threshold: 0
  dataflow_required: false
code_window:
  mode: "dynamic"
llm:
  mode: "tool_aware_chain"
  agent1_temperature: 0.0, max_tokens: 1024
  agent2_temperature: 0.1, max_tokens: 1024
  agent2_bias: "confirm_it"
  agent3_enabled: true, temperature: 0.1, max_tokens: 512
  enable_rag: true
post_process:
  enable_conflict_arbitration: true
  enable_confidence_calibration: true
  enable_quality_check: true
```

### 三级 Agent + Checklist 架构

```
有 sink 路径:                     无 sink 路径:
A1: 工具报告 → 窗口策略            A1: 工具报告 → full 窗口
A2: confirm_it 验证 sink          A2: checklist 六类审计
A3: checklist 补漏盲区              (合并到 A2)
```

### Prompt 设计

**A2 confirm_it (有 sink 验证)**:
```
- 假设 sink 可达，除非有硬证据不可达
- 清理措施有罪推定
- sizeof() 对变长数据不是保护
- 只有证明漏洞不可能时才判 safe
```

**A2 / A3 checklist (无 sink / 盲区)**:
```
逐项检查六大类:
1. MEMORY:   UAF / double-free / leak
2. INTEGER:  溢出 / 截断 / 符号转换
3. BOUNDARY: 越界 / off-by-one
4. CONCURRENCY: 竞态 / TOCTOU / 死锁
5. ERROR PATHS: 空指针 / 资源泄漏 / 返回值忽略
6. LOGIC:     条件错误 / 缺分支 / 索引越界
```

---

## 3. 关键修复历程

| # | 修复 | 效果 |
|---|------|------|
| 1 | AST 调用检测（CodeSlicer 不再误报变量名） | 消除 `SystemInfo* system` 类误报 |
| 2 | sanitizer_threshold=0 | 18/30 不再被静态决策跳过 |
| 3 | 完整代码替代截断 | A2 能看到漏洞所在代码行 |
| 4 | A1 措辞从 defeatist 改为 directive | A2 不被 A1 的低置信度毒化 |
| 5 | confirm_it 替换 flag_it | 召回从 0.07 跳到 0.87 |
| 6 | JSON 解析修复（数字后多余引号） | 消除 6/200 解析失败误报 |
| 7 | A1 输出简化（去数组、去 verification_focus） | 消除 28/30 解析失败 |
| 8 | checklist 六类审计替代通用全扫 | 无 sink F1 从 0.62 提到 0.74 |

---

## 4. 无 sink F1 演进

```
0.45 → 0.62 → 0.74
  ↑       ↑       ↑
截断代码  完整代码  结构化清单
+flag_it  +confirm  +confirm
```

---

## 5. 数据集发现

- **PrimeVul 标签噪声**: 93% vuln 样本 CWE 为空。验证发现 Chrome BUG=none 的功能 commit 被标为漏洞
- **BigVul 数据质量**: 99/100 旧测试集精确截断在 3000 字符；改用 MSR 原始完整函数版
- **短函数 F1 低**: 不是模型能力问题，是标签噪声在短函数中密度更高
- **RAG 无贡献**: CVE 元数据不含代码模式，语义空间不匹配

---

## 6. 与学术界对比

| 方法 | PrimeVul F1 | 备注 |
|------|-------------|------|
| StarCoder2 7B (ICSE '25) | 0.03 | 零样本 |
| CodeBERT 微调 (ICSE '25) | 0.21 | 有监督 |
| LLMxCPG (USENIX Security '25) | 0.62-0.68 | 需要 CPG 输入 |
| **V4 (本文)** | **0.77** | **零样本，无额外输入** |
