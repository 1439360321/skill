"""首页仪表板 -- 全局状态概览 + 快捷操作."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT.parent))


def render() -> None:
    st.title("首页概览")
    st.caption("LLM 代码审计平台")

    # =====================================================================
    # Row 1: Status cards
    # =====================================================================
    c1, c2, c3, c4 = st.columns(4)

    with c1:
        _stat_card_llm()
    with c2:
        model = st.session_state.get("llm_model", "glm-4.6v")
        _stat_card("当前模型", model)
    with c3:
        reports_dir = _ROOT / "reports"
        count = len(list(reports_dir.glob("*.json"))) if reports_dir.exists() else 0
        _stat_card("已保存报告", f"{count} 份")
    with c4:
        best_f1 = _get_best_f1(reports_dir)
        _stat_card("最高 F1-Score", best_f1)

    st.markdown("---")

    # =====================================================================
    # Row 2: Quick actions
    # =====================================================================
    st.markdown("### 快捷操作")
    qc1, qc2 = st.columns(2, gap="large")

    with qc1:
        with st.container(border=True):
            st.markdown("##### 代码扫描")
            st.caption("粘贴代码或上传文件，立即进行漏洞检测")

            preset = st.selectbox(
                "管道预设", ["v4", "v1", "v2", "v3"],
                format_func=lambda p: f"{p}: " + {
                    "v4": "工具感知链", "v1": "IRIS 聚焦",
                    "v2": "多温度投票", "v3": "单次调用",
                }[p],
                key="dashboard_scan_preset",
            )
            quick_code = st.text_area(
                "快速粘贴代码",
                height=100,
                placeholder="void foo(char *input) {\n    char buf[64];\n    strcpy(buf, input);\n}",
                key="dashboard_quick_code",
            )
            if st.button("打开扫描页", type="primary", use_container_width=True,
                         key="dashboard_scan_btn"):
                if quick_code.strip():
                    st.session_state.scan_quick_code = quick_code
                    st.session_state.scan_quick_preset = preset
                st.session_state.nav_page = "代码扫描"
                st.rerun()

    with qc2:
        with st.container(border=True):
            st.markdown("##### 批量评测")
            st.caption("在数据集上运行管道，计算 Precision / Recall / F1")

            DATASETS = {
                "BigVul (100 样本)": "bigvul_test_set.json",
                "Juliet (100 样本)": "juliet_test_set.json",
                "D2A (100 样本)": "d2a_test_set.json",
            }
            ds_label = st.selectbox(
                "数据集", list(DATASETS.keys()), key="dashboard_eval_dataset",
            )
            preset_eval = st.selectbox(
                "管道预设", ["v4", "v1", "v2", "v3"],
                format_func=lambda p: f"{p}: " + {
                    "v4": "工具感知链", "v1": "IRIS 聚焦",
                    "v2": "多温度投票", "v3": "单次调用",
                }[p],
                key="dashboard_eval_preset",
            )
            n_samples = st.slider("样本数量", 10, 100, 20, 10, key="dashboard_eval_n")

            if st.button("打开评测页", type="primary", use_container_width=True,
                         key="dashboard_eval_btn"):
                st.session_state.eval_quick_dataset = ds_label
                st.session_state.eval_quick_preset = preset_eval
                st.session_state.eval_quick_n = n_samples
                st.session_state.nav_page = "批量评测"
                st.rerun()

    st.markdown("---")

    # =====================================================================
    # Row 3: Recent activity
    # =====================================================================
    st.markdown("### 最近活动")

    activities: list[dict] = []

    for item in reversed(st.session_state.get("scan_history", [])[-10:]):
        activities.append({
            "type": "扫描",
            "time": item.get("timestamp", "?"),
            "detail": (
                f"语言={item.get('language','?')}  |  "
                f"预设={item.get('preset','?')}  |  "
                f"判定={item.get('verdict','?')}  |  "
                f"置信度={item.get('confidence',0):.2f}"
            ),
        })

    if reports_dir.exists():
        for p in sorted(reports_dir.glob("*.json"),
                        key=lambda x: x.stat().st_mtime, reverse=True)[:5]:
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                metrics = data.get("metrics", {})
                f1_str = f"F1={metrics.get('F1',0):.4f}" if metrics else "F1=?"
                activities.append({
                    "type": "评测",
                    "time": data.get("timestamp", time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime))),
                    "detail": (
                        f"数据集={data.get('dataset','?')}  |  "
                        f"预设={data.get('preset','?')}  |  "
                        f"样本={data.get('sample_count','?')}  |  "
                        f"{f1_str}"
                    ),
                })
            except Exception:
                pass

    activities.sort(key=lambda a: a["time"], reverse=True)

    if activities:
        for act in activities[:8]:
            tag_color = "#555" if act["type"] == "扫描" else "#555"
            st.markdown(f"""
            <div style="display:flex;align-items:flex-start;gap:12px;padding:8px 12px;
                        margin-bottom:2px;border-radius:6px;
                        border-bottom:1px solid #f2f2f2;">
                <span style="
                    display:inline-block;background:#f0f2f5;color:#555;
                    font-size:11px;font-weight:500;padding:2px 8px;border-radius:4px;
                    min-width:36px;text-align:center;flex-shrink:0;margin-top:2px;
                ">{act["type"]}</span>
                <div style="font-size:13px;line-height:1.6;">
                    <span style="color:#999;">{act["time"]}</span><br>
                    <span style="color:#444;">{act["detail"]}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("暂无活动记录。运行扫描或评测后，记录将显示在此处。")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stat_card_llm() -> None:
    """LLM 连接状态卡片。"""
    connected = st.session_state.get("llm_connected")
    if connected is True:
        text = "已连接"
        sub = "LLM 连接状态"
    elif connected is False:
        text = "未连接"
        sub = "LLM 连接状态"
    else:
        text = "未检测"
        sub = "LLM 连接状态"

    st.markdown(f"""
    <div style="
        background:#fff;border:1px solid #e8ecf0;border-radius:8px;
        padding:16px 18px;
    ">
        <div style="font-size:24px;font-weight:600;color:#111;line-height:1.2;">{text}</div>
        <div style="font-size:12px;color:#888;margin-top:2px;">{sub}</div>
    </div>
    """, unsafe_allow_html=True)


def _stat_card(label: str, value: str) -> None:
    """通用统计卡片。"""
    st.markdown(f"""
    <div style="
        background:#fff;border:1px solid #e8ecf0;border-radius:8px;
        padding:16px 18px;
    ">
        <div style="font-size:24px;font-weight:600;color:#111;line-height:1.2;">{value}</div>
        <div style="font-size:12px;color:#888;margin-top:2px;">{label}</div>
    </div>
    """, unsafe_allow_html=True)


def _get_best_f1(reports_dir: Path) -> str:
    if not reports_dir.exists():
        return "--"
    best = 0.0
    found = False
    for p in reports_dir.glob("*.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            f1 = data.get("metrics", {}).get("F1")
            if isinstance(f1, (int, float)) and f1 > best:
                best = f1
                found = True
        except Exception:
            pass
    return f"{best:.4f}" if found else "--"
