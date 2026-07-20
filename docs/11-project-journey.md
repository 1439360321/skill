# 项目探索历程

## 第一阶段：框架搭建（07-07 前）

**做了什么**：搭建基础框架——Streamlit 前端、本地 Ollama LLM 调用、tree-sitter AST 解析、sink 注册表。

**结论**：验证了"静态分析 + LLM"的技术可行性。但此时所有代码混在一起，评测体系不完整，无法量化每个模块的贡献。

**对最终版的贡献**：tree-sitter 解析器、sink 注册表沿用至今。

---

## 第二阶段：三阶段 LLM 管道（07-07 ~ 07-11）

**做了什么**：

- 在 sink 匹配基础上叠加三层优化：DataFlow（Source→Sink 数据流追踪）、Sanitization（正则匹配安全模式）、R1 三阶段 LLM（筛查→CoT 深度分析→自检）
- RAG 知识库：BigVul 案例 + ChromaDB + sentence-transformers
- 59 样本自建集评测

**发现了什么**：

三个"优化层"几乎都没有效果。DataFlow 硬过滤砍掉了含真漏洞的切片。Sanitization 10 个正则有 6 个不匹配真实代码。三阶段 LLM 对 F1 的贡献只有 +0.011（从 0.8657 到 0.8768），且 deepseek-r1:8b 对安全代码过度推理，40-120s/文件太慢。

**结论**：**小 LLM 的正确角色是"发现"而非"验证"**。LLM 应该弥补静态分析的盲区（逻辑漏洞），不应该重新发明静态分析已经做好的事（sink 匹配、sanitization 检测）。这个判断被证明是正确的，贯穿了后续所有设计。

**对最终版的贡献**：Sanitization 检测逻辑（CodeSlicer 沿用）；"LLM 做盲区"的核心思路。

---

## 第三阶段：九轮 Bug 修复（07-11）

**做了什么**：

在上一个阶段的基础上，用真实代码系统性地修复了 9 个 Bug：

1. Sanitization 正则重写——在真实样本而非理想化输入上测试
2. 双切片字节偏移修复——`func_code` 被二次切片，sanitization/dataflow 全跑在错误数据上
3. 风险评级重构——降级规则改为类别敏感的（`shell_escape` 对 `command_injection` 直接降为 low）
4. DataFlow 改为纯建议模式——不再硬过滤，仅影响置信度
5. Sink 优先级按风险排序——`gets`(high) 优先于 `printf`(medium)
6. 函数参数作为 Source——DataFlow 原来不识别函数参数
7. C 指针返回类型函数名提取——`void *func()` 被解析为 `pointer_declarator`
8. 补全标注数据——遗漏的真漏洞被标为 FP
9. Sink 恢复三个被过度移除的类别（free/malloc/open）

**结论**：此时的评测基于 59 样本自建集（F1>0.9，过拟合无区分度），"Sanitization >> DataFlow >> LLM" 的结论后来被推翻。但修复的底层 Bug（双切片、正则不匹配真实代码、风险评级）是正确的工程实践。

**对最终版的贡献**：CodeSlicer 的基础逻辑、风险评级体系、DataFlow 的辅助定位。但后续证明**LLM 才是最大变量**——confirm_it 把召回从 0.07 拉到 0.87，checklist 把无 sink F1 从 0.62 拉到 0.74。

---

## 第四阶段：管道模块化 + 换模型（07-11 ~ 07-13）

**做了什么**：

- 将原有管道拆分为可配置的模块化架构：静态决策层→代码窗口→LLM 策略→后处理
- 引入三套预设 V1/V2/V3（Agent 链/多温度投票/单次调用）
- 从 Ollama R1 切换到 GLM-4.6V（云 API）
- 定义了后续优化路线：CWE 专项 prompt、思维链、多 Agent 协作、结构化输入

**发现了什么**：

BigVul 52 样本评测揭示了一个核心矛盾——**LLM 管道层层杀 TP 不增 TP**。Agent1 筛掉 5-6 个 TP，Agent2 再杀 3-8 个，最终 TP 从 24（纯静态）降到 10-19（完整管道）。LLM 的价值只在 FP 削减，不会发现新的漏洞（至少对 GLM-4.6V 而言）。

同时发现了几个关键的反直觉结果：代码窗口的最佳值不是"越多越好"——`code[:1500]` F1=0.60，`code[:3000]` F1=0.42。函数开头（签名+声明）是最重要的上下文。多温度投票是双刃剑——≥2/3 共识过于保守。

**结论**：**sink 函数是注意力机制，不是漏洞本身**。`no_sink → 判安全` 在逻辑漏洞数据集上是错的。不同数据集需要不同的策略。这是后来三级 Agent 架构的思想起点。

**对最终版的贡献**：模块化管道架构（orchestrator + 预设）、CodeQL/Semgrep 批量运行器、评测体系。

---

## 第五阶段：开源项目优化（07-14 ~ 07-16）

**做了什么**（队友基于 `multi-agent-security-audit` 开源项目）：

- V0（基线）→ V7，8 轮迭代，在 BigVul（25 样本）和 PrimeVul（50 样本）上实验
- V1：修复 Evaluator 匹配逻辑（`file+func` → `file+func+vuln_type`）
- V2：修复数据流追踪——移除回退保底逻辑
- V3：sink 检测从子串匹配改为正则边界匹配 `\bfunc\s*\(`
- V4：Agent1 从单句推理改为 5 步 CoT——**失败**，F1 从 0.84 降到 0.76
- V5：加权投票（2-temp）+ 精度过滤倾向——无明显效果
- V6：CodeQL 集成 + RAG 知识注入——F1 略升
- V7：单次 LLM 结构化输出——token 消耗从 5x 降到 1x，F1 不变

**结论**：

1. **BigVul 最高 F1=0.85**（V1/V7），但 PrimeVul 遇到了根本问题：**FPR=1.0，安全样本全被误判**
2. CoT Prompt 让模型更谨慎→FN 增加——GLM-4.7-Flash 对 5 步推理指令的理解能力有限
3. **PrimeVul 的"安全"样本是被修复后的漏洞函数**（strcpy→strncpy），仍包含 sink，LLM 无法区分"有 sink 但被修复的代码"和"有 sink 的真正漏洞"
4. V7 的降本效果是最好的——单次 LLM 调用 F1 不变，token 砍 80%

**评价**：这个阶段把基础 Bug 修完了（evaluator 匹配、数据流、sink 子串匹配），token 从 5x 压到 1x。但 PrimeVul FPR=1.0 的瓶颈暴露了根本问题——单次 LLM 调用 + 简单的 prompt 无法区分"修复后仍含 sink 的代码"和"真正的漏洞"。

**对最终版的贡献**：单次调用的降本结论（V4 最后采用）、BigVul/PrimeVul 评估框架、静态决策层逻辑。

---

## 第六阶段：三级 Agent 架构 + 全线重构（07-19 ~ 07-20）

**做了什么**：

在队友工作的基础上，进行了架构性的重建：

### 架构设计

设计三级 Agent：A1（工具整合员，不读代码只读工具报告）、A2（聚焦裁判，动态窗口）、A3（盲区扫描器，只找漏洞不判安全）。核心思想来自前面的教训——单次 LLM 无法处理"有 sink 但是安全的代码"，需要分而治之。

### 基础设施

- RAG 向量库从 sentence-transformers segfault → ChromaDB ONNX → SiliconFlow bge-m3（免费，1024 维）
- 下载 NVD 25 万条 + CISA KEV 1,647 条建库（59,647 文档）
- 工具聚合器统一 CodeSlicer/CodeQL/Semgrep 输出
- 后处理链：冲突仲裁 + 置信度校准 + 输出质量检查

### 遗留清理

发现代码中残留大量历史包袱——`safe_patterns.py`、`numeric_vuln_detector.py` 等 regex 模块。在三层 Agent 架构下，regex 覆盖 LLM 判断反而成了拖累（`SafePatternsPostProcessor` 用"no dangerous function calls"覆盖了 LLM 正确的 UAF 检测）。将遗留代码迁入 `deprecated/`。

### 大规模调试

从 GLM-4.6V 切换到 DeepSeek V4 Flash（~¥1/200 样本），启动 PrimeVul 200 样本评测。发现并修复了 8 个隐藏问题：

1. **AST 调用检测**：CodeSlicer 用 `func_name in code` 字符串匹配，把 `SystemInfo* system` 变量声明误报为 `system()` 调用。改为 tree-sitter `call_expression` 遍历。

2. **静态决策拦杀**：`sanitizer_threshold=1` 导致 18/30 有 sink 样本被直接判 safe，LLM 完全未运行。改为 threshold=0。

3. **代码截断**：medium 窗口粗暴截取前 3000 字符，sink 在代码后半时 A2 看不到。medium/full 都改为完整代码。

4. **A1 措辞毒化 A2**：A1 的 "weak signal, low confidence" 暗示 A2 驳回。将 `verification_focus` 改为指令式，后来进一步简化为无数组格式（解决 A1 JSON 解析 28/30 失败）。

5. **A2 prompt 框架**：`flag_it` 下 A2 仍判 15/30 false_positive。发现是 prompt 框架问题——"Re-examine this finding" 暗示驳回。改为 `confirm_it`：假设 sink 可达、清理措施有罪推定、只有证明不可能才判 safe。**召回从 0.07 跳到 0.87**。

6. **JSON 解析**：DeepSeek V4 Flash 在数字值后多加引号（`1.0","`），一行正则修复。A1 输出含数组格式导致解析失败，简化为纯字符串。

7. **checklist 六类审计**：无 sink 场景下原 FULL_SCAN_PROMPT 太模糊（"找一切问题"）。改为结构化清单——MEMORY（UAF/双重释放/泄漏）、INTEGER（溢出/截断）、BOUNDARY（越界/off-by-one）、CONCURRENCY（竞态/TOCTOU）、ERROR PATHS（空指针/资源泄漏）、LOGIC（条件错误/分支缺陷）——逐项检查。**无 sink F1 从 0.62 提到 0.74**。

8. **RAG 验证**：消融实验确认 RAG 无贡献——查询返回的是 CVE 元数据而非代码模式，bge-m3 通用文本嵌入在代码-漏洞语义空间不匹配。

### 多条线索的交互验证

**flag_it → confirm_it 完整对比**（30 样本有 sink）：

| 策略 | F1 | P | R | FPR | A2 false_positive |
|------|-----|---|---|-----|-----|
| flag_it | 0.54 | 0.64 | 0.47 | 0.27 | 15/30 |
| confirm_it | 0.68 | 0.57 | 0.87 | 0.67 | 3/30 |

confirm_it 把 A2 从"驳回员"变成了"裁判"——false_positive 从 15 降到 3，召回从 0.47 跳到 0.87。代价是 FPR 从 0.27 升到 0.67。checklist 引入后，200 样本均衡下 FPR 降到 0.10。

**flag_it 在自然分布下的表现**：flag_it FPR=0.27 比 confirm_it 的 0.67 低很多，全量 PrimeVul 下 FP 会更少。但没跑过 flag_it 200 样本，无法确定。论文中可报两种策略的 tradeoff。

**短函数 vs 长函数**（200 样本，按代码长度分桶）：

| 长度 | n | F1 | P | R | sink% | A3% |
|------|---|---|---|---|-------|------|
| <500 | 81 | 0.36 | 0.31 | 0.44 | 2% | 0% |
| 500-1000 | 28 | 0.38 | 0.33 | 0.43 | 0% | 0% |
| 1000-2000 | 24 | 0.64 | 1.00 | 0.47 | 13% | 8% |
| 2000-3000 | 18 | 0.64 | 0.89 | 0.50 | 11% | 6% |
| >=3000 | 49 | **0.83** | **1.00** | 0.71 | 24% | 20% |

F1 随代码长度单调递增——长函数有更多上下文。>=1000 字符精确率近乎完美（0.89-1.00）。短函数的低 F1 有三重原因：JSON 解析失败（已修复）、标签噪声（Chrome BUG=none commit）、模型确实找不到（逻辑漏洞太隐蔽）。

**A1 在无 sink 路径上实质浪费**：90% 的样本无 sink→A1 只说"去看全部代码"→A2 全扫。此时三层架构坍缩为"一次 checklist 全扫 + 一次废调用"。这是当前架构的唯一冗余。

**自然分布 F1 估算**：

| | 分层 200 | 自然分布推算 |
|---|------|------|
| PrimeVul confirm_it | 0.77 | 0.16 |
| BigVul confirm_it | 0.67 | 0.16 |
| PrimeVul flag_it（估计） | — | ~0.22 |

自然分布 F1 全被极端不平衡主导（97% safe）。ICSE 2025 用 VD-S（FNR @ FPR≤0.5%）和分层采样来解决这个问题——论文应同时报告分层 F1 和自然 FPR。

**费用**：DeepSeek V4 Flash 输入 ¥1.00/M token，输出 ¥2.00/M token。200 样本约 ¥1，全量 PrimeVul 25,911 样本约 ¥77。

### 数据集分析

- 93% PrimeVul vuln 样本 CWE 为空。手工验证发现 Chrome BUG=none 的功能 commit 被标为漏洞
- BigVul 旧测试集 99/100 精确截断在 3000 字符，从 MSR 原始数据重建完整函数版本
- BigVul 自然分布 16:1（5.8% vuln），PrimeVul 36:1（2.7% vuln）
- BigVul 标签噪声估计 75%（ICSE 2025），导致 FPR=0.46 含水份

---

## 最终成绩

| | PrimeVul (200) | BigVul (200) |
|---|------|------|
| **F1** | **0.77** | **0.67** |
| Precision | 0.78 | 0.62 |
| Recall | 0.75 | 0.74 |
| FPR | 0.21 | 0.46 |
| 有 sink F1 | 0.88 | 0.75 |
| 无 sink F1 | 0.74 | 0.64 |

### 消融实验

| 配置 | F1 | P | R |
|------|-----|---|---|
| V3 基线（静态拦截+截断） | 0.18 | 0.29 | 0.13 |
| Fair 单次（完整代码+confirm_it，无Agent链） | 0.67 | 0.57 | 0.80 |
| V4 无 RAG | 0.70 | 0.54 | 1.00 |
| V4 完整 | 0.70 | 0.54 | 1.00 |

### 与学术界对比

| 方法 | PrimeVul F1 | 条件 |
|------|-------------|------|
| StarCoder2 7B | 0.03 | 零样本 |
| CodeBERT 微调 | 0.21 | 有监督 |
| LLMxCPG | 0.62-0.68 | 需要 CPG 结构化输入 |
| **本文** | **0.77** | **零样本，纯代码输入** |

---

## 各阶段贡献总结

| 阶段 | 核心贡献 | 是否正确 | 对最终版的帮助 |
|------|---------|------|------|
| 框架搭建 | tree-sitter + sink 注册表 | ✅ | 沿用至今 |
| 三阶段 LLM | "LLM 做盲区，不做验证" | ✅ | 三级 Agent 的思想起点 |
| 九轮 Bug 修复 | Sanitization >> DataFlow >> LLM | ❌（过拟合自建集）| 修好了底层Bug，但结论被后续推翻——LLM才是最大变量 |
| 管道模块化 | V1/V2/V3 预设、换模型 | ✅ | orchestrator 架构框架 |
| 开源项目优化 | 1x token、PrimeVul FPR=1.0 瓶颈 | ✅ | 证明单次 LLM 不够 |
| 三级 Agent + checklist | confirm_it + 六类审计清单 | ✅ | **F1 从 0.18→0.77** |
| RAG 验证 | CVE 元数据无贡献 | ✅（阴性结果）| 避免无效投入 |
