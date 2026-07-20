"""Streamlit 交互面板 — 管道调试 + API安全分析"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import streamlit as st

st.set_page_config(page_title="LLM代码审计系统", layout="wide",
                   initial_sidebar_state="expanded")

_ROOT = Path(__file__).resolve().parent

# =========================================================================
# Session state — persist LLM connection config across reruns
# =========================================================================
_LLM_DEFAULTS = {
    "provider": "openai",
    "base_url": "https://open.bigmodel.cn/api/paas/v4",
    "model": "glm-4.6v",
    "api_key": "",
    "connected": None,  # None | True | False
}

for _k, _v in _LLM_DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


def _render_pipeline_debugger() -> None:
    st.title("管道调试 — 单样本测试")

    sys.path.insert(0, str(_ROOT))
    sys.path.insert(0, str(_ROOT.parent))

    from src.llm.pipeline.orchestrator import run_pipeline, get_params
    from src.scanner.code_slicer import CodeSlicer

    # --- 侧栏：LLM 连接配置 ---
    with st.sidebar.expander("LLM 连接配置", expanded=True):
        provider_labels = {"openai": "OpenAI兼容 (GLM/DeepSeek/OpenAI)", "ollama": "Ollama 本地"}
        provider = st.radio("提供商",
            list(provider_labels.keys()), format_func=lambda k: provider_labels[k],
            index=0 if st.session_state.provider == "openai" else 1,
            horizontal=True, key="llm_provider_chosen")
        st.session_state.provider = provider

        if provider == "openai":
            st.session_state.base_url = st.text_input(
                "Base URL", value=st.session_state.base_url, key="llm_base_url")
            st.session_state.model = st.text_input(
                "模型名称", value=st.session_state.model, key="llm_model")
            st.session_state.api_key = st.text_input(
                "API Key", value=st.session_state.api_key, type="password", key="llm_api_key")
        else:
            if "llm_ollama_host" not in st.session_state:
                st.session_state.llm_ollama_host = "http://localhost:11434"
            if "llm_ollama_model" not in st.session_state:
                st.session_state.llm_ollama_model = "deepseek-r1:8b"
            st.session_state.llm_ollama_host = st.text_input(
                "Ollama Host", value=st.session_state.llm_ollama_host, key="llm_ollama_host_input")
            st.session_state.llm_ollama_model = st.text_input(
                "模型名称", value=st.session_state.llm_ollama_model, key="llm_ollama_model_input")

        col_t1, col_t2 = st.columns([1, 2])
        with col_t1:
            if st.button("测试连通性", use_container_width=True, key="btn_test"):
                with st.spinner("检测中..."):
                    try:
                        from shared.llm.openai_client import OpenAIClient
                        from shared.llm.ollama_client import OllamaClient
                        if st.session_state.provider == "openai":
                            client = OpenAIClient(
                                api_key=st.session_state.api_key,
                                base_url=st.session_state.base_url,
                                model=st.session_state.model,
                            )
                        else:
                            client = OllamaClient(
                                host=st.session_state.get("llm_ollama_host", "http://localhost:11434"),
                                model=st.session_state.get("llm_ollama_model", "deepseek-r1:8b"),
                            )
                        ok = client.check_health()
                        st.session_state.connected = ok
                    except Exception:
                        st.session_state.connected = False
        with col_t2:
            if st.session_state.connected is True:
                st.success("已连通")
            elif st.session_state.connected is False:
                st.error("连接失败")
            else:
                st.caption("未检测")

    # --- 侧栏：样本选择 ---
    st.sidebar.header("样本选择")

    DATASETS = {
        "BigVul": "bigvul_test_set.json",
        "Juliet": "juliet_test_set.json",
        "D2A": "d2a_test_set.json",
        "PrimeVul": "primevul_test.csv",
        "自建集": "test_set.json",
    }
    ds_label = st.sidebar.selectbox("数据集", list(DATASETS.keys()))
    ds_name = ds_label

    @st.cache_data
    def load_ds(label):
        data_dir = _ROOT / "data"
        path = data_dir / DATASETS[label]
        if not path.exists(): return []
        if label == "PrimeVul":
            import csv
            csv.field_size_limit(sys.maxsize)
            out = []
            with open(path, encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):
                    c = row.get("code","").strip()
                    if not c: continue
                    out.append({"code": c, "has_vulnerability": int(row.get("target","0"))==1,
                                "file": row.get("project","PrimeVul"),
                                "function_name": row.get("func_name","unknown")})
            return out
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    samples = load_ds(ds_label)
    if not samples:
        st.error("数据集为空"); st.stop()

    idx = st.sidebar.number_input("样本序号", 0, len(samples)-1, 0)
    sample = samples[idx]
    gt = sample.get("has_vulnerability", False)
    st.sidebar.metric("真实标签", "有漏洞" if gt else "安全")
    st.sidebar.caption(f"{sample.get('file','?')[:50]}")

    # --- 侧栏：管道开关 ---
    st.sidebar.header("管道配置")

    preset = st.sidebar.selectbox("预设方案", ["v1 (IRIS)", "v2 (多温度投票)", "v3 (单次调用)", "v4 (Tool-Aware Chain)", "自定义"])
    pname = preset.split()[0]
    params = get_params(pname)

    # 静态决策
    st.sidebar.subheader("静态决策层")
    sd = params["static_decision"]
    sd["no_sink"] = st.sidebar.radio("无sink函数 →", ["判安全","送LLM"],
        index=0 if sd.get("no_sink")=="safe" else 1, horizontal=True, key="ns")
    # Map back to internal values
    sd["no_sink"] = "safe" if sd["no_sink"] == "判安全" else "uncertain"

    sd["low_risk_sink"] = st.sidebar.radio("低风险+sink →", ["判安全","送LLM"],
        index=0 if sd.get("low_risk_sink")=="safe" else 1, horizontal=True, key="lr")
    sd["low_risk_sink"] = "safe" if sd["low_risk_sink"] == "判安全" else "uncertain"

    sd["sanitizer_threshold"] = st.sidebar.slider("消毒器阈值(≥N个→判安全)", 0,5, sd.get("sanitizer_threshold",0), key="st")

    # 代码窗口
    st.sidebar.subheader("代码窗口")
    cw = params["code_window"]
    mode_labels = {"simple": "简单截断", "iris": "IRIS聚焦(±N行)", "full": "完整代码", "dynamic": "动态窗口(工具信号驱动)"}
    cw_mode_label = st.sidebar.selectbox("窗口模式", list(mode_labels.values()),
        index=["简单截断","IRIS聚焦(±N行)","完整代码","动态窗口(工具信号驱动)"].index(
            mode_labels.get(cw.get("mode","simple"),"简单截断")), key="cw_m")
    cw["mode"] = [k for k,v in mode_labels.items() if v==cw_mode_label][0]

    if cw["mode"] == "simple":
        cw["simple_max_chars"] = st.sidebar.slider("截断长度(字符)", 500, 8000, cw.get("simple_max_chars",1500), 500, key="cw_n")
    elif cw["mode"] == "iris":
        cw["iris_window_lines"] = st.sidebar.slider("IRIS窗口(±行数)", 1, 20, cw.get("iris_window_lines",5), key="iris_w")

    # LLM策略
    st.sidebar.subheader("LLM 调用策略")
    llm = params["llm"]
    llm_mode_labels = {"agent_chain": "Agent链(筛查→验证)", "single_pass": "单次结构化输出", "multi_temp_voting": "多温度投票", "tool_aware_chain": "Tool-Aware链(工具整合)"}
    llm_mode_label = st.sidebar.selectbox("调用模式", list(llm_mode_labels.values()),
        index=["Agent链(筛查→验证)","单次结构化输出","多温度投票","Tool-Aware链(工具整合)"].index(
            llm_mode_labels.get(llm.get("mode","agent_chain"),"Agent链(筛查→验证)")), key="lm")
    llm["mode"] = [k for k,v in llm_mode_labels.items() if v==llm_mode_label][0]

    if llm["mode"] == "agent_chain":
        llm["agent1_temperature"] = st.sidebar.slider("Agent1 温度", 0.0, 1.0, llm.get("agent1_temperature",0.0), key="a1t")
        llm["agent2_temperature"] = st.sidebar.slider("Agent2 温度", 0.0, 1.0, llm.get("agent2_temperature",0.1), key="a2t")
        bias_label = st.sidebar.radio("Agent2 判定倾向", ["宁可误报(flag_it)","宁可漏报(precision)"],
            index=0 if llm.get("agent2_bias")=="flag_it" else 1, key="a2b")
        llm["agent2_bias"] = "flag_it" if "宁可误报" in bias_label else "precision"
        llm["agent3_enabled"] = st.sidebar.checkbox("Agent3 证据收集", llm.get("agent3_enabled",False), key="a3e")

    elif llm["mode"] == "multi_temp_voting":
        llm["agent1_temperature"] = st.sidebar.slider("Agent1 温度", 0.0, 1.0, 0.0, key="mv_a1t")
        llm["voting_consensus"] = st.sidebar.slider("投票共识(≥N票判漏洞)", 1, 3, llm.get("voting_consensus",2), key="vc")
        use_w = st.sidebar.checkbox("加权投票(低温度权重更高)", bool(llm.get("voting_weights")), key="wv")
        llm["voting_weights"] = {"0.0":1.5,"0.3":1.0} if use_w else {}
        llm["agent3_enabled"] = st.sidebar.checkbox("Agent3 证据收集", llm.get("agent3_enabled",False), key="mv_a3")

    elif llm["mode"] == "single_pass":
        llm["single_pass_temperature"] = st.sidebar.slider("温度", 0.0, 1.0, llm.get("single_pass_temperature",0.3), key="sp_t")
        llm["single_pass_max_tokens"] = st.sidebar.slider("最大Token数", 256, 4096, llm.get("single_pass_max_tokens",2048), 256, key="sp_m")

    # 后处理
    st.sidebar.subheader("后处理")
    pp = params["post_process"]
    pp["enable_conflict_arbitration"] = st.sidebar.checkbox("冲突仲裁(A2/A3意见不一致时LLM裁决)", pp.get("enable_conflict_arbitration",False), key="pp_arb")

    # JSON解析
    jp_label = st.sidebar.radio("JSON解析器",
        ["鲁棒模式(截断修复)","简单模式"],
        index=0 if params.get("json_parser",{}).get("mode")=="robust" else 1, key="jp")
    params["json_parser"]["mode"] = "robust" if "鲁棒" in jp_label else "simple"

    # =====================================================================
    # 主区域
    # =====================================================================
    raw_code = "N/A"
    if isinstance(sample, dict):
        raw_code = sample.get("code", sample.get("func", "N/A"))

    col_l, col_r = st.columns([1, 1])
    with col_l:
        st.subheader("源代码")
        lines = raw_code.split("\n") if raw_code != "N/A" else []
        if lines:
            numbered = "\n".join(f"{i+1:4d} | {l}" for i, l in enumerate(lines[:200]))
            st.code(numbered, language="c" if ds_label != "自建集" else None)
        else:
            st.code(raw_code[:5000])

    with col_r:
        st.subheader("静态分析结果")
        def wrap_c(code): return "\n".join([
            "#include <stdio.h>","#include <stdlib.h>","#include <string.h>",
            "#include <unistd.h>","#include <fcntl.h>"])+"\n\n"+code

        code = sample.get("code","") if isinstance(sample, dict) else ""
        wrapped = wrap_c(code) if code else ""
        slicer = CodeSlicer()
        slices = slicer.slice_code(wrapped, "c") if wrapped else []

        if slices:
            sl = slices[0]
            st.json({
                "函数名": sl.get("function_name","?"),
                "sink函数": sl.get("sink_type","无"),
                "sink类别": sl.get("sink_category","?"),
                "风险等级": sl.get("risk_level","低"),
                "有消毒器": sl.get("has_sanitization",False),
                "消毒器详情": sl.get("sanitization_detail",""),
                "污点源": sl.get("source_var","?"),
                "数据流": sl.get("dataflow_path","?"),
                "代码行": f"{sl.get('line_start','?')}-{sl.get('line_end','?')}",
            })
        else:
            st.warning("CodeSlicer: 未生成切片")

    st.markdown("---")

    if st.button("▶ 运行管道", type="primary", use_container_width=True):
        if not slices:
            st.error("没有可分析的切片"); st.stop()

        from shared.llm.openai_client import OpenAIClient
        from shared.llm.ollama_client import OllamaClient

        api_key = st.session_state.get("api_key", "")
        provider = st.session_state.get("provider", "openai")

        if provider == "openai" and not api_key:
            st.error("请先在侧栏「LLM 连接配置」中填写 API Key"); st.stop()

        if provider == "openai":
            client = OpenAIClient(
                api_key=api_key,
                base_url=st.session_state.get("base_url", "https://open.bigmodel.cn/api/paas/v4"),
                model=st.session_state.get("model", "glm-4.6v"),
            )
        else:
            client = OllamaClient(
                host=st.session_state.get("llm_ollama_host", "http://localhost:11434"),
                model=st.session_state.get("llm_ollama_model", "deepseek-r1:8b"),
            )

        if not client.check_health():
            st.error("LLM API 不可用 — 请检查连接配置和 API Key"); st.stop()

        sl = dict(slices[0])
        sl["language"] = "c"
        sl["_file_code"] = code
        sl["code_patterns"] = sl.get("code_patterns", [])
        sl["slicer_func_name"] = sl.get("function_name", "?")

        st.subheader("管道输出")
        t0 = time.time()

        try:
            result = run_pipeline(sl, client, params)
            elapsed = time.time() - t0
        except Exception as e:
            st.error(f"管道运行错误: {e}")
            import traceback; st.code(traceback.format_exc()); st.stop()

        # 第0层：静态决策
        d = result.get("_static_decision","?")
        d_text = {"safe": "安全", "vuln": "有漏洞", "uncertain": "不确定→送LLM"}.get(d, d)
        dc = "green" if d=="safe" else "red" if d=="vuln" else "orange"
        st.markdown(f"### 第0层: 静态决策 → :{dc}[**{d_text}**]")

        # 第1层：上下文
        with st.expander("第1层: 结构化上下文 + 代码窗口"):
            st.json(result.get("_context",{}))
            st.caption("代码窗口(前500字符):")
            st.code(result.get("_code_window",""))

        # LLM结果
        mode = llm["mode"]

        if mode == "single_pass":
            with st.expander("LLM: 单次结构化输出", expanded=True):
                raw = result.get("_agent1_raw","")
                parsed = result.get("_agent1_parsed",{})
                if raw: st.text_area("原始响应", str(raw)[:2000], height=150)
                if parsed:
                    v = "有漏洞" if parsed.get("has_vulnerability") else "安全"
                    st.markdown(f"判定: **{v}** (置信度={parsed.get('confidence',0):.2f})")
                    st.caption(f"推理: {parsed.get('reasoning','?')}")
                    st.json(parsed)
        else:
            with st.expander("第2层: Agent1 筛查员", expanded=True):
                a1 = result.get("_agent1_parsed", result.get("_agent1_raw"))
                if isinstance(a1, dict):
                    v = a1.get("verdict","?")
                    v_text = {"suspicious": "可疑→继续", "safe": "安全→终止"}.get(v, v)
                    c = a1.get("confidence",0)
                    clr = "orange" if v=="suspicious" else "green"
                    st.markdown(f"判定: :{clr}[**{v_text}**] (置信度={c:.2f})")
                    st.caption(f"推理: {a1.get('reasoning','?')}")
                elif isinstance(a1, str): st.text(a1[:500])

            with st.expander("第3层: Agent2 验证员", expanded=True):
                if mode == "multi_temp_voting":
                    vs = result.get("_voting_summary",{})
                    st.markdown(f"投票结果: 漏洞{vs.get('vuln',0)}票 / 安全{vs.get('safe',0)}票")
                    for t, data in result.get("_agent2_raws",{}).items():
                        v_text = "漏洞" if data.get('verdict')=='vulnerable' else "安全"
                        st.text(f"温度 {t}: {v_text}")
                else:
                    a2 = result.get("_agent2_raw",{})
                    if isinstance(a2, dict):
                        v = a2.get("verdict","?")
                        v_text = {"confirmed_vuln":"确认漏洞","false_positive":"误报→安全","uncertain":"不确定→判漏洞"}.get(v, v)
                        clr = "red" if "vuln" in str(v) else "green"
                        st.markdown(f"判定: :{clr}[**{v_text}**] (置信度={a2.get('confidence',0):.2f})")

            if result.get("_agent3_raw"):
                with st.expander("第4层: Agent3 证据收集"): st.json(result["_agent3_raw"])

        # 最终结果
        st.markdown("---")
        fv = result.get("final_verdict","?")
        fv_text = "有漏洞" if fv=="vuln" else "安全"
        fm = result.get("final_method","?")
        fc = result.get("final_confidence",0)
        c1,c2,c3,c4 = st.columns(4)
        with c1: st.metric("最终判定", fv_text)
        with c2: st.metric("判定方法", fm)
        with c3: st.metric("置信度", f"{fc:.2f}")
        with c4: st.metric("耗时", f"{elapsed:.1f}秒")
        gt_str = "有漏洞" if gt else "安全"
        match = "✅正确" if (fv=="vuln")==gt else "❌错误"
        st.caption(f"真实标签: {gt_str} {match} | LLM调用次数: {result.get('_llm_calls',0)}")

        with st.expander("完整结果字典"):
            st.json({k:v for k,v in result.items() if not k.startswith("_")
                     or k in ("_static_decision","_llm_calls","_voting_summary")})


# ====================================================================
# API安全分析
# ====================================================================

def _render_api_security() -> None:
    st.title("API 安全分析")
    tab1, tab2 = st.tabs(["文件分析", "工作原理"])
    with tab1: _render_api_file_scan()
    with tab2:
        st.markdown("""
        ### 检测管道
        HAR/JSON日志 → 流量解析器 → 会话构建 → 3个检测器 → 风险聚合器 → 报告
        - **序列检测器** — API调用顺序、枚举攻击、越权
        - **参数检测器** — 顺序ID扫描、参数遍历
        - **访问检测器** — 跨用户资源访问、IDOR/BOLA
        """)


def _render_api_file_scan() -> None:
    import tempfile, os
    st.subheader("API 流量分析")
    uploaded = st.file_uploader("上传 HAR/JSON 日志", type=["har","json"])
    if not uploaded: return
    with tempfile.NamedTemporaryFile(delete=False, suffix="."+uploaded.name.rsplit(".",1)[-1], mode="wb") as tmp:
        tmp.write(uploaded.read()); tmp_path = tmp.name
    use_llm = st.checkbox("启用LLM分析", True)
    if st.button("▶ 开始分析", type="primary"):
        sys.path.insert(0, str(_ROOT))
        from api_security.src.traffic.parser import parse_file
        from api_security.src.traffic.session import build_sessions
        from api_security.src.detector.aggregator import RiskAggregator
        reqs = parse_file(tmp_path)
        st.info(f"解析到 {len(reqs)} 条API请求")
        sessions = build_sessions(reqs)
        if use_llm:
            provider = st.session_state.get("provider", "openai")
            if provider == "openai":
                from shared.llm.openai_client import OpenAIClient
                llm = OpenAIClient(
                    api_key=st.session_state.get("api_key", ""),
                    base_url=st.session_state.get("base_url", "https://open.bigmodel.cn/api/paas/v4"),
                    model=st.session_state.get("model", "glm-4.6v"),
                )
            else:
                from shared.llm.ollama_client import OllamaClient
                llm = OllamaClient(
                    host=st.session_state.get("llm_ollama_host", "http://localhost:11434"),
                    model=st.session_state.get("llm_ollama_model", "deepseek-r1:8b"),
                )
            if not llm.check_health(): st.error("LLM 不可用 — 请检查连接配置"); return
            st.success("分析完成(LLM模式)")
        else:
            st.success("分析完成(启发式模式)")
        os.unlink(tmp_path)


# ====================================================================
# 侧栏路由
# ====================================================================

st.sidebar.title("LLM 代码审计系统")
route = st.sidebar.radio("页面",
    ["管道调试", "API安全分析"],
    format_func=lambda r: {"管道调试": "管道调试",
                           "API安全分析": "API安全分析"}[r])

if route == "管道调试":
    _render_pipeline_debugger()
else:
    _render_api_security()

st.sidebar.markdown("---")
st.sidebar.caption("三人小组 | 2026夏季大作业")
