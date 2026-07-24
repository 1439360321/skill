"""LLM 代码审计平台 -- 多页面 Streamlit 应用 V2."""
from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

st.set_page_config(
    page_title="LLM 代码审计系统",
    layout="wide",
    initial_sidebar_state="expanded",
)

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT.parent))

from app.components.llm_utils import load_config  # noqa: E402

# =====================================================================
# Session state defaults
# =====================================================================
_DEFAULTS = {
    "llm_provider": "openai",
    "llm_base_url": "https://open.bigmodel.cn/api/paas/v4",
    "llm_model": "glm-4.6v",
    "llm_api_key": "",
    "llm_ollama_host": "http://localhost:11434",
    "llm_ollama_model": "deepseek-r1:8b",
    "llm_connected": None,
    "pipeline_preset": "v4",
    "pipeline_params_override": {},
    "scan_history": [],
    "nav_page": "首页概览",
}

# Load persisted config first (overrides defaults)
_persisted = load_config()
for key, value in _DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = _persisted.get(key, value)

# =====================================================================
# Clean minimal CSS
# =====================================================================
st.markdown("""
<style>
    /* ===== SIDEBAR ===== */
    [data-testid="stSidebar"] {
        background: #e9ecf0;
        border-right: 1px solid #d8dce2;
    }
    [data-testid="stSidebar"] h3 {
        font-size: 1rem !important;
        font-weight: 600 !important;
        color: #1a1a1a !important;
    }
    [data-testid="stSidebar"] hr {
        border-color: #e8ecf0 !important;
    }
    [data-testid="stSidebar"] .stButton button {
        border-radius: 6px !important;
        text-align: left !important;
        padding: 10px 14px !important;
        font-size: 13px !important;
        font-weight: 500 !important;
        margin-bottom: 2px !important;
        transition: background 0.15s !important;
    }
    [data-testid="stSidebar"] .stButton button[kind="secondary"] {
        background: transparent !important;
        border: 1px solid transparent !important;
        color: #555 !important;
    }
    [data-testid="stSidebar"] .stButton button[kind="secondary"]:hover {
        background: #f0f2f5 !important;
        border-color: #e0e3e8 !important;
        color: #111 !important;
    }
    [data-testid="stSidebar"] .stButton button[kind="primary"] {
        background: #2c2c2c !important;
        border: 1px solid #1a1a1a !important;
        color: #fff !important;
    }
    [data-testid="stSidebar"] .stButton button[kind="primary"][disabled] {
        background: #444 !important;
        border-color: #333 !important;
        opacity: 0.85 !important;
    }
    [data-testid="stSidebar"] caption {
        color: #888 !important;
    }

    /* ===== MAIN CONTENT ===== */
    .main .block-container {
        padding-top: 1.5rem;
        max-width: 1400px;
    }
    h1 {
        font-size: 1.6rem !important;
        font-weight: 600 !important;
        color: #111 !important;
    }
    h3, h4 {
        color: #333 !important;
        font-weight: 600 !important;
    }

    /* ===== CARDS ===== */
    [data-testid="stVerticalBlockBorderWrapper"] {
        border-radius: 8px !important;
        border-color: #e8ecf0 !important;
        box-shadow: none !important;
    }

    /* ===== METRICS ===== */
    [data-testid="stMetric"] {
        background: #fff;
        border: 1px solid #e8ecf0;
        border-radius: 8px;
        padding: 14px 18px;
        box-shadow: none;
    }
    [data-testid="stMetric"] label {
        font-size: 0.75rem !important;
        color: #888 !important;
        font-weight: 400 !important;
    }
    [data-testid="stMetric"] [data-testid="stMetricValue"] {
        font-size: 1.5rem !important;
        font-weight: 600 !important;
        color: #111 !important;
    }

    /* ===== BUTTONS ===== */
    .stButton > button[kind="primary"] {
        border-radius: 6px !important;
        font-weight: 500 !important;
    }
    .stButton > button[kind="primary"]:not([disabled]) {
        background: #2c2c2c !important;
        border-color: #1a1a1a !important;
    }

    /* ===== EXPANDERS ===== */
    [data-testid="stExpander"] {
        border: 1px solid #e8ecf0 !important;
        border-radius: 8px !important;
        background: #fff !important;
        margin-bottom: 6px !important;
    }

    /* ===== INPUTS ===== */
    textarea {
        font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace !important;
        font-size: 13px !important;
        line-height: 1.5 !important;
    }

    /* ===== DATAFRAMES ===== */
    [data-testid="stDataFrame"] {
        border-radius: 8px !important;
        border: 1px solid #e8ecf0 !important;
    }

    /* ===== ALERTS ===== */
    [data-testid="stAlert"] {
        border-radius: 8px !important;
    }

    /* ===== DIVIDER ===== */
    hr {
        margin: 14px 0 !important;
        border-color: #e8ecf0 !important;
    }

    /* ===== STATUS DOT ===== */
    .status-dot {
        display: inline-block; width: 7px; height: 7px;
        border-radius: 50%; margin-right: 5px;
    }
    .status-dot.online { background: #22c55e; }
    .status-dot.offline { background: #ef4444; }
    .status-dot.unknown { background: #bbb; }
</style>
""", unsafe_allow_html=True)

# =====================================================================
# Sidebar — clean navigation
# =====================================================================
with st.sidebar:
    st.markdown("### LLM 代码审计")
    st.caption("多 Agent 漏洞检测平台")

    st.markdown("---")

    NAV = [
        ("首页概览", "dashboard"),
        ("代码扫描", "scanner"),
        ("批量评测", "evaluation"),
        ("报告历史", "history"),
    ]

    current = st.session_state.nav_page

    for label, _key in NAV:
        active = current == label
        if active:
            st.button(
                label, key=f"nav_{label}",
                use_container_width=True, type="primary", disabled=True,
            )
        else:
            if st.button(
                label, key=f"nav_{label}",
                use_container_width=True, type="secondary",
            ):
                st.session_state.nav_page = label
                st.rerun()

    st.markdown("---")

    # LLM status indicator
    connected = st.session_state.get("llm_connected")
    model = st.session_state.get("llm_model", "?")
    if connected is True:
        dot_class = "online"
        status_text = "已连接"
    elif connected is False:
        dot_class = "offline"
        status_text = "未连接"
    else:
        dot_class = "unknown"
        status_text = "未检测"

    st.markdown(f"""
    <div style="display:flex;align-items:center;gap:7px;padding:7px 10px;
                background:#fff;border-radius:6px;border:1px solid #e8ecf0;">
        <span class="status-dot {dot_class}"></span>
        <div style="font-size:11px;line-height:1.3;color:#555 !important;">
            {status_text}<br><span style="color:#888 !important;font-size:10px;">{model}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.caption("")

    if st.button("设置", key="nav_settings", use_container_width=True,
                 type="secondary"):
        st.session_state.nav_page = "设置"
        st.rerun()

    # Footer
    st.caption("")
    reports_dir = _ROOT / "reports"
    if reports_dir.exists():
        n = len(list(reports_dir.glob("*.json")))
        st.caption(f"报告: {n} 份")
    else:
        st.caption("暂无报告")

# =====================================================================
# Page routing
# =====================================================================
current_page = st.session_state.nav_page

if current_page == "首页概览":
    from app.pages.dashboard import render
    render()
elif current_page == "代码扫描":
    from app.pages.scanner import render
    render()
elif current_page == "批量评测":
    from app.pages.evaluation import render
    render()
elif current_page == "设置":
    from app.pages.config import render
    render()
elif current_page == "报告历史":
    from app.pages.history import render
    render()
