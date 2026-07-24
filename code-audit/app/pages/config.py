"""设置页 -- LLM 连接 + 管道预设对比 + 高级参数 + 导出."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT.parent))

from app.components.llm_utils import get_llm_client, test_llm_connection


def render() -> None:
    st.title("设置")
    st.caption("LLM 连接配置、管道预设对比、高级参数微调")

    tab1, tab2, tab3, tab4 = st.tabs(
        ["LLM 连接", "预设对比", "高级参数", "导出配置"]
    )

    with tab1:
        _render_llm_config()
    with tab2:
        _render_preset_comparison()
    with tab3:
        _render_advanced_params()
    with tab4:
        _render_export()


# ===========================================================================
# Tab 1: LLM Connection
# ===========================================================================

def _render_llm_config() -> None:
    """LLM 连接配置面板。"""

    # Defaults
    for key, default in [
        ("llm_provider", "openai"),
        ("llm_base_url", "https://open.bigmodel.cn/api/paas/v4"),
        ("llm_model", "glm-4.6v"),
        ("llm_api_key", ""),
        ("llm_ollama_host", "http://localhost:11434"),
        ("llm_ollama_model", "deepseek-r1:8b"),
        ("llm_connected", None),
    ]:
        if key not in st.session_state:
            st.session_state[key] = default

    # Quick switch pills
    st.markdown("#### 快速切换")
    qc1, qc2, qc3 = st.columns(3)
    with qc1:
        if st.button("GLM-4.6v (智谱 AI)", use_container_width=True, key="cfg_glm_btn"):
            st.session_state.llm_provider = "openai"
            st.session_state.llm_base_url = "https://open.bigmodel.cn/api/paas/v4"
            st.session_state.llm_model = "glm-4.6v"
            st.session_state.llm_connected = None
            st.rerun()
    with qc2:
        if st.button("DeepSeek V4 Flash", use_container_width=True, key="cfg_ds_btn"):
            st.session_state.llm_provider = "openai"
            st.session_state.llm_base_url = "https://api.deepseek.com"
            st.session_state.llm_model = "deepseek-chat"
            st.session_state.llm_connected = None
            st.rerun()
    with qc3:
        if st.button("Ollama 本地部署", use_container_width=True, key="cfg_ollama_btn"):
            st.session_state.llm_provider = "ollama"
            st.session_state.llm_connected = None
            st.rerun()

    st.markdown("---")

    # Provider
    provider = st.selectbox(
        "提供商",
        ["openai", "ollama"],
        format_func=lambda p: {"openai": "云端 API (GLM/DeepSeek)", "ollama": "Ollama 本地"}[p],
        index=0 if st.session_state.llm_provider == "openai" else 1,
        key="cfg_provider",
    )
    st.session_state.llm_provider = provider

    col_a, col_b = st.columns([2, 1])

    if provider == "openai":
        with col_a:
            st.session_state.llm_base_url = st.text_input(
                "接口地址", value=st.session_state.llm_base_url, key="cfg_base_url",
            )
            st.session_state.llm_model = st.text_input(
                "模型名称", value=st.session_state.llm_model, key="cfg_model",
            )
            st.session_state.llm_api_key = st.text_input(
                "API 密钥", value=st.session_state.llm_api_key,
                type="password", key="cfg_api_key",
            )
            if st.session_state.llm_api_key.startswith("${"):
                st.warning("API Key 仍是占位符 `${...}`，请在 `.env` 中配置实际 Key")
        with col_b:
            _render_connection_status("openai")
    else:
        with col_a:
            st.session_state.llm_ollama_host = st.text_input(
                "主机地址", value=st.session_state.llm_ollama_host, key="cfg_ollama_host",
            )
            st.session_state.llm_ollama_model = st.text_input(
                "模型名称", value=st.session_state.llm_ollama_model, key="cfg_ollama_model",
            )
        with col_b:
            _render_connection_status("ollama")

    st.caption("API Key 通过 `.env` 文件加载，不会提交到 Git。")

    # auto-persist config so it survives browser refresh
    from app.components.llm_utils import save_config
    save_config()


def _render_connection_status(provider: str) -> None:
    """连接状态面板。"""
    st.markdown("##### 连接状态")

    if st.button("测试连接", use_container_width=True,
                 key=f"cfg_test_{provider}"):
        with st.spinner("正在测试..."):
            ok = test_llm_connection()
        if ok:
            st.success("连接成功")
        else:
            st.error("连接失败")

    connected = st.session_state.get("llm_connected")
    if connected is True:
        model = st.session_state.get("llm_model", "?")
        st.success(f"已连通: {model}")
    elif connected is False:
        st.error("连接失败 -- 请检查配置")
    else:
        st.info("尚未检测")


# ===========================================================================
# Tab 2: Preset Comparison
# ===========================================================================

def _render_preset_comparison() -> None:
    from src.llm.pipeline.orchestrator import get_params

    presets = {
        "V1 IRIS Agent 链": get_params("v1"),
        "V2 多温度投票": get_params("v2"),
        "V3 激进单次": get_params("v3"),
        "V4 工具感知链 (推荐)": get_params("v4"),
    }

    st.markdown("### 预设方案参数对比")

    rows = []
    for name, p in presets.items():
        sd = p.get("static_decision", {})
        cw = p.get("code_window", {})
        llm = p.get("llm", {})
        pp = p.get("post_process", {})
        rows.append({
            "预设": name,
            "代码窗口": cw.get("mode", "?"),
            "LLM 策略": llm.get("mode", "?"),
            "无 Sink 处理": sd.get("no_sink", "?"),
            "低风险处理": sd.get("low_risk_sink", "?"),
            "消毒器阈值": sd.get("sanitizer_threshold", 0),
            "冲突仲裁": "开" if pp.get("enable_conflict_arbitration") else "关",
            "置信度校准": "开" if pp.get("enable_confidence_calibration") else "关",
        })

    import pandas as pd
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.markdown("### 完整参数 JSON")
    for name, p in presets.items():
        with st.expander(name):
            st.json(p)


# ===========================================================================
# Tab 3: Advanced Parameters
# ===========================================================================

def _render_advanced_params() -> None:
    from src.llm.pipeline.orchestrator import get_params

    st.markdown("### 高级参数覆写")
    st.caption("修改仅对本次会话生效。重置恢复预设默认值。")

    preset = st.selectbox(
        "基于预设", ["v1", "v2", "v3", "v4"],
        format_func=lambda p: f"{p}: " + {
            "v1": "IRIS Agent 链", "v2": "多温度投票",
            "v3": "单次调用", "v4": "工具感知链",
        }[p],
        key="cfg_adv_preset",
    )
    params = get_params(preset)

    col_a, col_b = st.columns(2)

    with col_a:
        with st.expander("第0层: 静态决策", expanded=False):
            sd = params["static_decision"]
            no_sink = st.selectbox(
                "无 Sink 行为", ["safe", "uncertain", "vuln"],
                index=["safe", "uncertain", "vuln"].index(sd.get("no_sink", "uncertain")),
                key="adv_no_sink",
                format_func=lambda x: {"safe": "安全", "uncertain": "不确定 (送LLM)", "vuln": "判漏洞"}[x],
            )
            low_risk = st.selectbox(
                "低风险 Sink 行为", ["safe", "uncertain"],
                index=0 if sd.get("low_risk_sink") == "safe" else 1,
                key="adv_low_risk",
                format_func=lambda x: {"safe": "安全", "uncertain": "不确定 (送LLM)"}[x],
            )
            san_thresh = st.slider(
                "消毒器阈值", 0, 5, sd.get("sanitizer_threshold", 0), key="adv_san",
            )
            st.session_state.pipeline_params_override = {
                "static_decision": {
                    "no_sink": no_sink,
                    "low_risk_sink": low_risk,
                    "sanitizer_threshold": san_thresh,
                }
            }

        with st.expander("第1层: 代码窗口", expanded=False):
            cw = params["code_window"]
            mode = st.selectbox(
                "窗口模式", ["iris", "simple", "dynamic"],
                index=["iris", "simple", "dynamic"].index(cw.get("mode", "simple")),
                key="adv_cw_mode",
            )
            st.caption("iris = 聚焦 Sink 周围 | simple = 完整函数 | dynamic = 自适应")

    with col_b:
        with st.expander("第2层: LLM 策略", expanded=False):
            llm = params["llm"]
            modes = ["agent_chain", "multi_temp_voting", "single_pass", "tool_aware_chain"]
            mode = st.selectbox(
                "策略模式", modes,
                index=modes.index(llm.get("mode", "agent_chain")),
                key="adv_llm_mode",
            )
            st.caption(
                "agent_chain / multi_temp_voting / single_pass / tool_aware_chain"
            )

        with st.expander("后处理", expanded=False):
            pp = params["post_process"]
            arb = st.checkbox("冲突仲裁", pp.get("enable_conflict_arbitration", True), key="adv_arb")
            cal = st.checkbox("置信度校准", pp.get("enable_confidence_calibration", True), key="adv_cal")
            override = getattr(st.session_state, "pipeline_params_override", {})
            override["post_process"] = {
                "enable_conflict_arbitration": arb,
                "enable_confidence_calibration": cal,
            }
            st.session_state.pipeline_params_override = override

    c_btn1, c_btn2, _ = st.columns([1, 1, 3])
    with c_btn1:
        if st.button("应用覆写", use_container_width=True, key="cfg_apply"):
            st.success("已应用 -- 切换到扫描或评测页即可使用")
    with c_btn2:
        if st.button("重置为默认", use_container_width=True, key="cfg_reset"):
            st.session_state.pipeline_params_override = {}
            st.success("已重置")


# ===========================================================================
# Tab 4: Export
# ===========================================================================

def _render_export() -> None:
    st.markdown("### 导出配置")
    st.caption("下载当前会话配置，用于分享或备份。")

    export = {
        "llm": {
            "provider": st.session_state.get("llm_provider", "openai"),
            "base_url": st.session_state.get("llm_base_url", ""),
            "model": st.session_state.get("llm_model", ""),
        },
        "pipeline_preset": st.session_state.get("pipeline_preset", "v4"),
        "pipeline_params_override": st.session_state.get("pipeline_params_override", {}),
    }

    st.json(export)
    st.download_button(
        "下载配置 (JSON)",
        data=json.dumps(export, indent=2, ensure_ascii=False),
        file_name="pipeline_config.json",
        mime="application/json",
    )
