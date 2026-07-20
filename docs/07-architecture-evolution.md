# 管道架构演进记录

## 一、起点：模块化管道 + 三套预设

初始架构已具备模块化管道，所有参数可独立调节。核心流程：

```
样本加载 → 静态决策层 → 代码窗口 → LLM调用策略 → 后处理 → 结果输出
```

三套预设：v1 IRIS（Agent链 2-3次LLM）、v2 多温度投票（4-5次）、v3 单次结构化输出（1次）。

## 二、sink 函数的本质

### 2.1 sink 是注意力机制，不是漏洞本身

CodeSlicer 的核心机制是 sink 驱动——识别危险函数调用（strcpy、system 等），追踪用户输入流向。这个机制在面对 buffer overflow、命令注入等「必须经过某个危险函数」的漏洞类型时有效，但无法检测不依赖特定函数调用的逻辑错误。

sink 的作用是告诉分析器「这里可能有坑，聚焦这里」——它是信号，不是判定。将 `no_sink → 判安全` 等同于没有漏洞，是混淆了信号和结论。

### 2.2 不同数据集的漏洞类型分布

| 数据集 | 漏洞主力 | sink 特征 | no_sink→判安全 安全性 |
|--------|---------|-----------|:---:|
| BigVul | buffer overflow (CWE-119/120) | 明显 | 基本安全，偶有遗漏 |
| Juliet | 合成测试用例，全 sink 型 | 明显 | 完全安全 |
| D2A | UAF、double-free、竞态 | 弱/无 | **大量漏报** |
| PrimeVul | off-by-one、整数溢出 | 弱/无 | **大量漏报** |

测试 D2A/PrimeVul 等逻辑错误数据集时，`no_sink → 送LLM` 是必要的。

### 2.3 有 sink 不等于此处就是漏洞

同一段代码里，工具高共识指向 sink 区域，但真正的漏洞可能隐藏在工具全部沉默的另一段逻辑中：

```c
strcpy(buf, input);          // 所有工具指向这里
// ... 50行正常逻辑 ...
free(g_ctx->ptr);            // 真正UAF，工具全沉默
g_ctx->cleanup(g_ctx->ptr);  // 第72行，盲区
```

工具共识引导视线，但视线之外才是盲区的藏身之处。这也是为什么需要 Agent3 做全局扫描。

## 三、多工具静态分析层

### 3.1 工具对比矩阵

| 工具 | 原理 | 检测逻辑错误 | 关键盲区 |
|------|------|:---:|------|
| **CodeSlicer** | AST遍历 + 单函数数据流 + sink注册表 | 否 | 不跨函数、不追踪指针别名、不做控制流时序分析 |
| **CodeQL** | 编译级CFG/DFG + 61条预置C/C++安全查询 | 是 | --build-mode=none下跨函数弱、语法必须合法、单函数片段上下文有限 |
| **Flawfinder** | 词法模式匹配 + 内置危险函数库 | 否 | 只看函数名不做语义。Juliet CWE-121: 4968 TP vs 27735 FP |
| **Cppcheck** | 自定义C/C++解析器 + 数据流/控制流分析 | 部分 | 误报率最低但召回率极低。UAF检出接近0% |
| **Semgrep** | AST模式匹配（Python） | 否 | 浅层语法匹配，不做语义推理 |

### 3.2 能力矩阵

| 漏洞类型 | CodeSlicer | CodeQL | Flawfinder | Cppcheck |
|---------|:--:|:--:|:--:|:--:|
| buffer overflow (strcpy) | 可 | 可 | 可 | 可 |
| 命令注入 (system) | 可 | 可 | 可 | 可 |
| UAF / double-free | 不可 | **可** | 不可 | 极少 |
| 整数溢出 | 部分(正则) | **可** | 不可 | 部分 |
| off-by-one | 部分(正则) | **可** | 不可 | 不可 |
| 竞态/TOCTOU | 不可 | 部分 | 不可 | 不可 |

### 3.3 学术界验证：SAST + LLM 组合

2024-2025年多篇论文验证了这个方向。核心结论：

- **SAST提供低误报的结构化信号，LLM提供高召回的语义理解，组合互补双方短板**（Zhou et al., 2024，15个SAST + 12个LLM对比）
- **SAST-Genius**：Semgrep + Llama3 → 精度 35.7% → **89.5%**，误报减 91%
- **LLM4FPM**：精确代码切片 + Qwen → F1 98.9%，FP降 85%，消融实验证明精确切片最关键
- **消融实验共识**：喂给LLM最有用的是精确的代码切片 + SAST数据流轨迹，工具名贡献最小

## 四、三级 Agent 架构

### 4.1 架构总览

```
静态分析层（零 LLM token）
  Flawfinder + CodeQL + Cppcheck + CodeSlicer
         ↓ 结构化报告（~300 tokens）
Agent1：工具整合员（不看代码）
  找出共识/矛盾/盲区风险 → 输出审查要点
         ↓ 审查要点（~200 tokens） + 窗口建议
Agent2：聚焦判定员（看代码，动态窗口）
  flag_it 倾向，在工具指向区域内做深度判定
         ↓ 判断结果
Agent3：盲区扫描器（看完整代码）
  precision 倾向，审查Agent2视野外的所有区域
  仅在 Agent2 判 safe/uncertain 时触发
```

### 4.2 Agent1：工具整合员

**设计理由：** Flawfinder 一个文件能吐几百条命中，全灌给最终裁判上下文直接爆。Agent1 不看代码，只看结构化工具报告，token 消耗 ~300。

**输入：** 四个工具的结构化 JSON + 每个工具的已知盲区说明

**任务：** 做差异分析而非漏洞判定——找出一致点、矛盾点、盲区风险

**输出三个信号：**

1. **共识点：** 多个工具一致指向的行号和 CWE 类型
2. **矛盾点：** 工具间结论冲突的位置
3. **盲区风险：** 所有工具可能集体遗漏的漏洞类型（如："CodeQL在build-mode=none下UAF检测弱，如果该代码涉及动态内存管理，扩大审查范围"）

### 4.3 Agent2：聚焦判定员

**倾向：** flag_it（宁可误报）

**代码窗口由工具信号强度动态决定：**

| 信号强度 | 窗口策略 | Token |
|---------|---------|------|
| 高共识（2+工具指向同一区域） | IRIS ±5行 | 低 |
| 中信号（1个工具发现） | 中等窗口 3000字符 | 中 |
| 无信号（工具全沉默） | 完整代码 | 高 |

### 4.4 Agent3：盲区扫描器

**触发条件：** 仅在 Agent2 判 safe 或 uncertain 时触发。Agent2 判 vuln 则跳过（工具共识 + LLM一致 = 高置信）。

**倾向：** precision（宁可漏报），翻案门槛 ≥0.8 + 具体行号

**Prompt 设计要点：**

1. 承认 Agent2 对已审区域的判断，不重新争论
2. 核心任务：审查 Agent2 视野之外的代码内容
3. 如果整个函数无新增可疑点 → 直接返回 safe（输出短）

**Agent3 不是「另一个裁判」，而是「盲区扫描器」**——不给 Agent2 抢活干，只做 Agent2 因聚焦窗口而无法做到的事。

### 4.5 Token 效率

| 架构 | 平均 LLM 调用次数 | Agent 分工 |
|------|-------------------|-----------|
| v1 Agent链 | 2-3 | 都看代码，重复 |
| v2 多温度投票 | 4-5 | 同prompt不同温度，冗余 |
| v3 单次调用 | 1 | 最快但无分工 |
| **三级架构** | **1 + 1 + 0.3 ≈ 2.3** | Agent1不看代码(~300t)，Agent3低频触发 |

## 五、截断哲学

### 5.1 为什么截断

三个原因，按重要性排序：

1. **注意力聚焦：** LLM 有「迷失在中间」问题——长上下文时开头和结尾权重高，中间被忽视。截断本质是帮LLM聚焦
2. **成本控制：** 批量评估的 token 费用不可完全忽视
3. **响应时间：** 输入量与首 token 延迟正相关

### 5.2 不是「装不下了才截」，是「有方向才截」

```
无工具指引：截断是盲狙，可能把漏洞代码截没
有工具指引：IRIS 窗口 ±N行围绕发现 = 精准聚焦
```

### 5.3 信号驱动的动态策略

截断策略不应一刀切：

```
工具信号强    → 截狠 → 省 token，信任工具
工具信号弱    → 扩窗 → 给 LLM 更多上下文
工具完全沉默  → 完整代码 → LLM 自己找，工具帮不上忙
```

动态窗口策略即基于工具报告中的 source 数量自动选择窗口大小，无需用户手动切换。

## 六、后处理增强

### 6.1 从正则到 LLM 驱动

原始后处理只是两个正则检查（safe_patterns + numeric_vuln）。在三级架构下，Agent2和Agent3可能给出不同结论，后处理的重要性明显提升。

### 6.2 新增处理器

| 处理器 | LLM 成本 | 功能 |
|--------|:--:|------|
| **ConflictArbitrator** | 1次短调用(~50t) | A2与A3矛盾时做仲裁。不看代码只看推理过程。规则：A3发现的新问题在A2窗口外→A3对；A3理由模糊→A2对；两者各有道理→可同时成立 |
| **ConfidenceCalibrator** | 零 | 两Agent一致→+0.1；矛盾→-0.1；措辞模糊→扣分；工具共识→加微量。纯规则 |
| **OutputQualityChecker** | 零 | 无理由判vuln→降置信；过度自信(>0.95但理由短)→纠正；A2判safe但最终判vuln且无A3→警告 |

### 6.3 触发链

```
SafePatterns → NumericVuln → ConfidenceCalibration → QualityCheck
                              (始终开启)
                                              ↓
                                    如果 A2≠A3 矛盾
                                              ↓
                                    ConflictArbitrator
                                    (一次短LLM调用)
```

## 七、RAG 知识库

### 7.1 数据源

不使用 BigVul 建库（测试集泄漏）。使用三个独立数据源：

| 数据源 | 规模 | 获取方式 | 用途 |
|--------|------|---------|------|
| **CISA KEV** | 1,647条 | 直链 JSON，秒下 | 实际被利用的漏洞，检索优先 |
| **NVD 全量** | 25万+ CVE | API 批量拉取，4-6小时 | 全量 CVE 描述 + CWE + CVSS |
| **CVEfixes**（可选） | 1.2万 | Zenodo 下载 | 真实修复 diff 做 few-shot |

### 7.2 嵌入模型演进

```
ONNX all-MiniLM-L6-v2 (384维)  →  本地免费，代码描述跨模态匹配弱
        ↓ (segfault on sentence-transformers)
SiliconFlow Qwen3-Embedding-0.6B (1024维)  →  代码专项训练，付费 ~¥0.20/全量
        ↓ (用户要求用免费模型)
SiliconFlow BAAI/bge-m3 (1024维)  →  多语言，免费，零成本建库
```

### 7.3 管道接入点

检索结果注入 Agent3 的 prompt 中，作为历史参考案例：
```
"以下是与当前代码相似的已知漏洞案例，供参考：
 CVE-2023-4911 (CWE-122): GNU C Library buffer overflow in ld.so..."
```

## 八、缓存层

### 8.1 设计

`CacheManager`（`src/utils/cache.py`）基于 pickle + MD5 哈希 + TTL 过期。

**Key 组成：** `md5(代码前200字符 + sink + 语言) _ md5(参数JSON)`

保证：同一样本+同一套参数 → 命中缓存；改任何参数 → 重新计算

### 8.2 接入策略

- `run_pipeline()` 开头查缓存 → 命中直接返回（含 `_cache_hit: True` 标记）
- 仅 LLM 路径结果写入缓存（静态决策的确定性结果不写，省磁盘）
- Config 控制：`cache.enabled` + `cache.ttl_hours`

## 九、LLM 连接配置

### 9.1 Streamlit 面板

侧栏顶部「LLM 连接配置」expander，支持：
- 提供商：OpenAI兼容（GLM/DeepSeek/OpenAI）/ Ollama 本地
- Base URL、模型名、API Key 填写
- 「测试连通性」按钮：创建临时 client → ping一次 → 显示结果
- 通过 `st.session_state` 持久化，刷新不丢失

### 9.2 环境变量管理

API Key 统一在 `.env` 文件管理，git-ignored：
```
GLM_API_KEY=xxx
NVD_API_KEY=xxx
SILICONFLOW_API_KEY=xxx
```

## 十、待实现模块清单

| 优先级 | 模块 | 详细说明 |
|--------|------|---------|
| **P0** | Flawfinder/Cppcheck CLI 包装器 | 和 codeql_runner.py 同模式：临时文件 + subprocess + 解析输出 |
| **P0** | 工具结果聚合器 | 去重（同行号±2、同CWE）、CWE归一化、source 标注 |
| **P0** | ToolAwareChainStrategy | 三级Agent新 LLM mode，与现有三种并列 |
| **P1** | RAG 接入 Agent3 | NVD入库后，Agent3 prompt中注入历史案例 |
| **P1** | eval脚本改造 | 加 `--mode tool_aware_chain` 支持批量评估 |
| **P2** | Streamlit 面板更新 | CodeQL toggle、flawfinder/cppcheck checkbox、tool_aware_chain 入口 |
| **P2** | Prompt 微调 | CWE_COT_PROMPTS 针对新架构精简 |
| **P3** | 多文件关联 | 测试集不涉及，真实项目级扫描时有意义 |
| **P3** | 批量样本队列 | Streamlit 一次测N个样本，输出统计摘要 |
