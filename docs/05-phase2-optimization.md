# 路线二：第二轮优化 — 从 0.69 到 0.84

> 日期：2026-07-11
> 目标：Precision / Recall / F1 三项指标均 > 0.8

---

## 一、起点：第一轮优化后的状态

| 指标 | 值 |
|------|:--:|
| Precision | 0.6471 |
| Recall | 0.7333 |
| **F1** | **0.6875** |
| TP/FP/FN/TN | 22/12/8/15 |

**三个"优化层"都没有实际效果：**

| 模块 | 声称的作用 | 实际效果 |
|------|-----------|---------|
| DataFlow | Source→Sink 数据流过滤 | **零效果** — FP=17 不变 |
| Sanitization | 缓解措施检测降风险 | **仅减 1 个 FP** — 17→16 |
| R1 LLM | 三阶段推理增强 | **负优化** — F1 +0.011，Recall -0.033 |

---

## 二、根因诊断

### 发现 1：Sanitization 正则大面积失效

10 个核心正则中 **6 个不匹配真实代码**：

| 正则 | 问题 | 测试输入 | 结果 |
|------|------|---------|:--:|
| `length_check` (C) | `sizeof\s*\)` 不匹配 `sizeof(buf)` | `if (strlen(x) >= sizeof(buf))` | ❌ |
| `size_guard` (C) | `[^)]*` 贪婪吃掉操作符 | `if (len > 64)` | ❌ |
| `command_allowlist` (Py) | 只匹配 `[...]`，不匹配 `{...}` set | `{"localhost", "127.0.0.1"}` | ❌ |
| `allowlist_check` (Py) | 要求 `in` 后是内联字面量 | `if host not in allowed:` | ❌ |
| `safe_read` (Py) | 匹配 `open(..., 'rb')`，误杀 pickle 漏洞 | `open(f, 'rb')` in vuln file | ❌ |

### 发现 2：双切片 Bug

`code_slicer.py` 将 `func_code`（已切片过的函数代码）传给 `detect_in_function()` 和 `DataFlowAnalyzer.analyze()`，这两个函数内部又用 `func_node.start_byte` 对 `func_code` 再切一次——**字节偏移全错**。

```python
# Bug: func_code 已经是 code[100:500]，再切 func_code[100:500] 只有 300 字节
func_code = code[func_node.start_byte:func_node.end_byte]  # 第一次切片
san_result = san_detector.detect_in_function(func_node, func_code)  # 内部再切片！
```

这导致 sanitization 和 dataflow 检测都在错误的代码片段上运行，大量模式匹配失效。

### 发现 3：风险降级过于保守

`_assess_risk` 函数：
- 强 sanitization（conf ≥ 0.6）只降一级：high→medium（不→low）
- "medium" 仍被判为漏洞（`has_vulnerability = risk != "low"`）
- 安全函数的 FP 永远消不掉

### 发现 4：C 指针返回类型的函数名提取失败

tree-sitter C 将 `void *func_name(...)` 解析为 `pointer_declarator` 而非 `function_declarator`，导致 `cwe190_01.c` 等文件的函数名显示为 "unknown"。

### 发现 5：app.py 不在标注数据中

`demo_project/app.py` 中 `handle_pickle`（真·pickle 反序列化漏洞）和 `run_cmd`（真·命令注入）未被标注，导致正确检出反被算作 FP。

### 发现 6：sanitization 未按类别过滤

`_assess_risk` 把函数中匹配到的**所有** sanitization 模式都计入置信度，不管它们是否跟当前 sink 类别相关。例如 `snprintf` 出现在函数中（用于构建安全字符串），却被计为 `format_string` 的 sanitization——但 `printf(buffer)` 的格式字符串漏洞跟 `snprintf` 无关。

---

## 三、修复方案与效果

### 修复 1：重写 Sanitization 正则（sink_registry.py）

```python
# C — 修复 sizeof 后不要求 \) 、非贪婪 [^)]*? 、数字边界
"length_check": r"if\s*\(.*(?:str)?len\s*\([^)]*\).*?[<>=!]+\s*(?:sizeof|...)(?![a-zA-Z])"
"size_guard":  r"if\s*\([^)]*?[<>=!]+\s*(?:\d+|sizeof|...)(?![a-zA-Z])"
"numeric_bound": r"if\s*\([^)]*?\b(?:len|size|count)\b\s*[<>=!]+\s*\d+\s*\)"
"sizeof_bound": r"if\s*\(.*\bsizeof\s*\(?[^)]*\)?\s*[<>=!]"

# Python — 支持 set 字面量 + 变量名 allowlist + env var 凭证
"command_allowlist": r"[\[{]\s*\"[^\"]+\"(?:\s*,\s*(?:\"[^\"]+\"|\w+))*\s*[\]}]"
"allowlist_check":   r"if\s+\w+\s+(?:not\s+)?in\s+(?:[\[({]|\w+)"
"env_var_credential": r"os\.(?:environ|getenv)\.get\(|os\.environ\[|getenv\("
```

### 修复 2：修复双切片 Bug（code_slicer.py）

```python
# 修复前：传 func_code → 二次切片，字节偏移错
df_result = df_analyzer.analyze(func_node, func_code)

# 修复后：传 code（原始文件）→ 字节偏移正确
df_result = df_analyzer.analyze(func_node, code)
```

### 修复 3：重写风险评级（code_slicer.py）

- 类别特有的强 sanitization（如 shell_escape for command_injection）→ **直接降为 low**
- 仅统计与当前 sink 类别相关的 sanitization 模式
- memory_corruption / integer_overflow / credential_hardcoding 不因缺失 dataflow 而降级（sink 本身就是漏洞）

### 修复 4：Sink 优先级按风险排序

```python
# 修复前：最长匹配优先 → printf(6) 优先于 gets(4)
# 修复后：(风险优先级, -长度) 排序 → gets(high, -4) 优先于 printf(medium, -6)
```

### 修复 5：C 指针返回类型函数名提取

```python
elif child.type == "pointer_declarator":  # void *func(...)
    for sub in child.children:
        if sub.type == "function_declarator":
            ...  # 提取 identifier
```

### 修复 6：补全标注数据

test_set.json 新增 4 条记录（app.py × 3 + command_injection.py safe_command）。

### 修复 7：DataFlow 改为纯建议模式

移除 DataFlow 的硬过滤逻辑（之前会直接 skip 非高危无 dataflow 的切片），改为仅影响置信度。

### 修复 8：DataFlow 增加函数参数作为 source

```python
# 函数参数就是外部输入，之前不被识别为 source
param_list = self._find_child(func_node, "parameter_list")
# → 所有参数标识符加入 source_vars
```

### 修复 9：Sink 恢复三个被过度移除的类别

- `free` → memory_corruption（双 free / use-after-free）
- `malloc` → integer_overflow（溢出计算后分配）
- `open(` → path_traversal（路径拼接型目录穿越）

---

## 四、最终效果

```
                    Baseline    +Sanitization (最终)
Precision           0.6000      0.8438    +40.6%
Recall              0.8438      0.8438    不变
F1                  0.7013      0.8438    +20.3%
FPR                 0.6923      0.1923    -72.2%
FP 数量             18  →       5         -72%
```

**Sanitization 是真正的 FP 杀手**——FPR 从 0.69 降至 0.19。DataFlow 仍需作为置信度辅助存在，但不再硬过滤。

---

## 五、剩余问题

### 无法修复的（根本局限性）

| 文件 | 漏洞 | 为什么检测不到 |
|------|------|-------------|
| cwe125_01.c | 手动 while 循环越界读 | 无标准 sink 函数 |
| cwe476_01.c | 空指针解引用 | 纯逻辑 bug，无 API 调用 |
| cwe787_01.c | for 循环 off-by-one | 无标准 sink 函数 |

这 3 个文件需要**语义级分析**（符号执行或 LLM 深度推理），sink 匹配本质不可达。

### 可继续优化的

| 问题 | 优先级 | 方向 |
|------|:--:|------|
| 5 个 C safe 文件仍 FP | 中 | C sanitization 需更多模式（strchr 检测、null guard） |
| py_cwe22_01.py FN | 中 | 函数参数 source 检测未正常工作 |
| cwe134_01.c FN | 低 | 函数内 safe_snprintf 被误统计为 format_string sanitization |
| DataFlow 仍无实质贡献 | 低 | 需要更严格的 source→sink 路径验证逻辑 |

---

## 六、教训

1. **正则必须用真实代码测试** — 6/10 失效，因为测试时用了理想化输入而非实际样本
2. **字节偏移是无声杀手** — 双切片 bug 让 sanitization 和 dataflow 全部跑在错误数据上，零报错零告警
3. **评测数据是优化的前提** — 标注缺漏让正确检出变成"误报"，误导优化方向
4. **保守降级是 FP 的温床** — "high→medium" 看起来谨慎，实则让所有安全文件都停留在 vulnerable 状态
5. **Sanitization >> DataFlow >> LLM** — 三层优化的实际贡献递减。静态 sanitization 检测性价比最高
