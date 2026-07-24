"""指标展示 -- F1/Precision/Recall/FPR 卡片和混淆矩阵."""
from __future__ import annotations

import streamlit as st


def render_metrics(metrics: dict) -> None:
    """渲染一行 4 个指标卡片: F1, Precision, Recall, FPR。"""
    f1 = metrics.get("F1", 0)
    prec = metrics.get("Precision", 0)
    rec = metrics.get("Recall", 0)
    fpr = metrics.get("FPR", 0)

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric("F1-Score", f"{f1:.4f}")
    with c2:
        st.metric("精确率", f"{prec:.4f}")
    with c3:
        st.metric("召回率", f"{rec:.4f}")
    with c4:
        st.metric("FPR", f"{fpr:.4f}")


def render_confusion(tp: int, fp: int, fn_val: int, tn: int) -> None:
    """渲染混淆矩阵 -- 2x2 网格布局。"""
    total = tp + fp + fn_val + tn
    if total == 0:
        st.caption("无数据")
        return

    st.markdown("#### 混淆矩阵")

    r1c1, r1c2 = st.columns(2)
    with r1c1:
        st.metric("TP 正确检出", tp)
    with r1c2:
        st.metric("FP 误报", fp)

    r2c1, r2c2 = st.columns(2)
    with r2c1:
        st.metric("FN 漏报", fn_val)
    with r2c2:
        st.metric("TN 正确排除", tn)

    correct = tp + tn
    wrong = fp + fn_val
    st.caption(
        f"正确率: {correct}/{total} = {correct/total:.1%}  |  "
        f"误报+漏报: {wrong}/{total} = {wrong/total:.1%}"
    )


def render_detector_metrics(detector_results: dict) -> None:
    """按检测器分组展示指标。"""
    if not detector_results:
        return
    st.markdown("#### 按检测器分组")
    rows = []
    for det, m in sorted(detector_results.items()):
        rows.append({
            "检测器": det,
            "F1": f"{m.get('F1', 0):.4f}",
            "Precision": f"{m.get('Precision', 0):.4f}",
            "Recall": f"{m.get('Recall', 0):.4f}",
            "TP": m.get("TP", 0),
            "FP": m.get("FP", 0),
            "FN": m.get("FN", 0),
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)
