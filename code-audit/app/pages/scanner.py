"""代码扫描页 -- 上传/粘贴代码 -> 扫描 -> 结果."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT.parent))

from app.components.llm_utils import get_llm_client
from app.components.code_viewer import render_code
from app.components.pipeline_viz import render_pipeline_result

CWE_REF = {
    "system":   "CWE-78 OS 命令注入",
    "popen":    "CWE-78 OS 命令注入",
    "exec":     "CWE-94 代码注入",
    "eval":     "CWE-95 Eval 注入",
    "strcpy":   "CWE-120 缓冲区溢出 (无边界检查)",
    "strcat":   "CWE-120 缓冲区溢出 (无边界检查)",
    "sprintf":  "CWE-120 缓冲区溢出 (格式化)",
    "gets":     "CWE-242 危险函数",
    "scanf":    "CWE-120 缓冲区溢出 (无界输入)",
    "memcpy":   "CWE-122 堆缓冲区溢出",
    "free":     "CWE-416 释放后使用",
    "malloc":   "CWE-789 不受控内存分配",
    "fopen":    "CWE-22 路径遍历",
    "recv":     "CWE-120 缓冲区溢出 (网络)",
    "read":     "CWE-120 缓冲区溢出 (文件描述符)",
}

PRESET_OPTIONS = ["v4", "v1", "v2", "v3"]
PRESET_LABELS = {
    "v4": "v4 工具感知链",
    "v1": "v1 IRIS 聚焦",
    "v2": "v2 多温度投票",
    "v3": "v3 单次调用",
}
PRESET_INFO = {
    "v1": "IRIS 聚焦 + Agent 链 (筛查 -> 验证 -> 证据)",
    "v2": "简单窗口 + 多温度投票验证",
    "v3": "激进静态 + 单次 LLM 调用 (最快)",
    "v4": "工具感知链 + RAG (F1 最高, 推荐)",
}


def render() -> None:
    st.title("代码安全扫描")
    st.caption("上传源代码文件或直接粘贴代码，LLM 管道自动检测漏洞")

    # =====================================================================
    # Top control bar
    # =====================================================================
    ctl1, ctl2, ctl3, ctl4 = st.columns([1, 1, 1, 1])

    with ctl1:
        language = st.selectbox("语言", ["c", "python", "java"], key="scan_lang")
    with ctl2:
        preset = st.selectbox(
            "管道预设", PRESET_OPTIONS,
            format_func=lambda p: PRESET_LABELS[p],
            key="scan_preset",
        )
    with ctl3:
        input_mode = st.selectbox(
            "输入方式", ["粘贴代码", "上传文件"], key="scan_input_mode",
        )
    with ctl4:
        st.caption(PRESET_INFO.get(preset, ""))

    # =====================================================================
    # Code input area
    # =====================================================================
    code: str = ""

    if input_mode == "粘贴代码":
        quick_code = st.session_state.pop("scan_quick_code", "")
        quick_preset = st.session_state.pop("scan_quick_preset", "")
        if quick_preset:
            st.session_state.scan_preset = quick_preset

        code = st.text_area(
            "源代码",
            value=quick_code,
            height=320,
            placeholder=(
                "void foo(char *input) {\n"
                "    char buf[64];\n"
                "    strcpy(buf, input);\n"
                "}"
            ),
            key="scan_code_input",
        )
    else:
        uploaded = st.file_uploader(
            "上传源文件", type=["c", "h", "py", "java"], key="scan_upload",
        )
        if uploaded:
            code = uploaded.read().decode("utf-8", errors="ignore")
            name = uploaded.name
            if name.endswith((".py", ".pyw")):
                language = "python"
            elif name.endswith(".java"):
                language = "java"
            st.caption(f"已加载: {name} ({len(code)} 字符)")
            st.code(code[:500] + ("..." if len(code) > 500 else ""), language=language)

    can_scan = bool(code.strip())

    scan_col, info_col, _ = st.columns([2, 2, 6])
    with scan_col:
        if st.button("开始扫描", type="primary", use_container_width=True,
                     disabled=not can_scan, key="scan_btn"):
            with st.spinner():
                _do_scan(code, language, preset)
    with info_col:
        if can_scan:
            st.caption(f"{len(code)} 字符 / {len(code.splitlines())} 行")

    # =====================================================================
    # Results
    # =====================================================================
    scan_data = st.session_state.get("_scan_data")
    if scan_data:
        _render_scan_results(scan_data)

    if not scan_data and not can_scan:
        _render_empty_prompt()

    # =====================================================================
    # CWE reference
    # =====================================================================
    st.markdown("---")
    with st.expander("Sink 函数 -> CWE 对照表", expanded=False):
        st.dataframe(
            [{"Sink 函数": k, "CWE": v} for k, v in sorted(CWE_REF.items())],
            use_container_width=True, hide_index=True, height=320,
        )


# ===========================================================================
# Scan execution
# ===========================================================================

def _do_scan(code: str, language: str, preset_key: str) -> None:
    from src.scanner.code_slicer import CodeSlicer
    from src.llm.pipeline.orchestrator import run_pipeline, get_params

    client = get_llm_client()
    if client is None:
        st.error("请先在设置页配置 LLM 连接并填入 API Key")
        return

    try:
        if not client.check_health():
            st.error("LLM API 不可用 -- 请检查设置页的连接配置")
            return
    except Exception as e:
        st.error(f"连接失败: {e}")
        return

    t0_slice = time.time()
    slicer = CodeSlicer()
    if language == "c":
        wrapped = "\n".join([
            "#include <stdio.h>", "#include <stdlib.h>", "#include <string.h>",
            "#include <unistd.h>", "#include <fcntl.h>",
        ]) + "\n\n" + code
    else:
        wrapped = code
    slices = slicer.slice_code(wrapped, language)
    t_slice = time.time() - t0_slice

    if not slices:
        slices = [{
            "file": "input", "function_name": "main", "language": language,
            "code": wrapped, "sink_type": "__no_sink__", "sink_category": "generic",
            "risk_level": "medium", "source_var": "unknown",
            "sanitization_detail": "", "dataflow_path": "",
        }]

    sl = slices[0]
    sink = sl.get("sink_type", "?")
    cwe = CWE_REF.get(sink, "")

    params = get_params(preset_key)
    t0_pipe = time.time()

    try:
        result = run_pipeline(dict(sl), client, params)
        elapsed = time.time() - t0_pipe
    except Exception as e:
        st.error(f"管道错误: {e}")
        import traceback
        st.code(traceback.format_exc())
        return

    line_nums = result.get("line_numbers", [])
    if isinstance(line_nums, list) and len(line_nums) == 2:
        hl = list(range(line_nums[0], line_nums[1] + 1))
    elif isinstance(line_nums, list):
        hl = line_nums
    else:
        hl = []

    st.session_state._scan_data = {
        "code": code, "language": language, "preset": preset_key,
        "sl": sl, "sink": sink, "cwe": cwe,
        "t_slice": t_slice, "result": result, "elapsed": elapsed,
        "highlight_lines": hl,
    }

    if "scan_history" not in st.session_state:
        st.session_state.scan_history = []
    st.session_state.scan_history.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "code": code[:200], "language": language, "preset": preset_key,
        "verdict": result.get("final_verdict", "?"),
        "confidence": result.get("final_confidence", 0),
        "elapsed": round(t_slice + elapsed, 1),
    })


# ===========================================================================
# Results rendering
# ===========================================================================

def _render_scan_results(data: dict) -> None:
    code = data["code"]
    language = data["language"]
    sl = data["sl"]
    sink = data["sink"]
    cwe = data["cwe"]
    t_slice = data["t_slice"]
    result = data["result"]
    elapsed = data["elapsed"]
    hl = data["highlight_lines"]

    st.markdown("---")
    st.markdown("### 扫描结果")

    # Static analysis
    st.markdown("#### 静态分析")
    sc1, sc2, sc3, sc4 = st.columns(4)
    with sc1:
        st.metric("函数", sl.get("function_name", "?"))
    with sc2:
        st.metric("Sink 函数", sink)
    with sc3:
        st.metric("风险等级", sl.get("risk_level", "low"))
    with sc4:
        st.metric("切片耗时", f"{t_slice:.2f}s")
    if cwe:
        st.info(f"Sink 函数 `{sink}` -> {cwe}")

    # Pipeline result
    st.markdown("#### 管道分析")
    render_pipeline_result(result, elapsed)

    # Timing
    with st.expander("耗时分解", expanded=False):
        tc1, tc2, tc3 = st.columns(3)
        with tc1:
            st.metric("切片", f"{t_slice:.2f}s")
        with tc2:
            st.metric("LLM 管道", f"{elapsed:.2f}s")
        with tc3:
            st.metric("总计", f"{t_slice + elapsed:.2f}s")

    # Code review
    st.markdown("#### 代码审查")
    render_code(code, language, highlight_lines=hl if hl else None)

    # Export
    st.markdown("---")
    export = {
        "时间": time.strftime("%Y-%m-%d %H:%M:%S"),
        "语言": language, "预设": data["preset"],
        "函数": sl.get("function_name", "?"), "Sink": sink,
        "风险等级": sl.get("risk_level", "?"),
        "判定": result.get("final_verdict", "?"),
        "置信度": result.get("final_confidence", 0),
        "方法": result.get("final_method", "?"),
        "LLM 调用次数": result.get("_llm_calls", 0),
        "总耗时": round(t_slice + elapsed, 2),
    }
    st.download_button(
        "导出结果 (JSON)",
        data=json.dumps(export, indent=2, ensure_ascii=False),
        file_name=f"scan_{time.strftime('%H%M%S')}.json",
        mime="application/json",
    )

    if st.button("清除结果", key="scan_clear"):
        del st.session_state._scan_data
        st.rerun()


def _render_empty_prompt() -> None:
    st.markdown("""
    <div style="
        background:#fafbfc;border:2px dashed #e0e4e8;border-radius:10px;
        padding:48px 24px;text-align:center;margin:24px 0;
    ">
        <div style="font-size:15px;color:#999;margin-bottom:8px;">
            开始安全审计
        </div>
        <div style="font-size:13px;color:#bbb;">
            在上方粘贴源代码或上传文件，选择管道预设后点击"开始扫描"<br>
            管道将自动进行静态分析、LLM 审查和漏洞判定
        </div>
    </div>
    """, unsafe_allow_html=True)
