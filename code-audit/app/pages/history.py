"""报告历史页 -- 查看、对比、删除已保存的扫描/评测结果."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT.parent))

from app.components.metrics_card import render_metrics, render_confusion


def render() -> None:
    st.title("报告历史")
    st.caption("查看、对比和管理已保存的评测结果")

    reports_dir = _ROOT / "reports"
    reports = sorted(
        reports_dir.glob("*.json"),
        key=lambda p: p.stat().st_mtime, reverse=True,
    ) if reports_dir.exists() else []

    if not reports:
        _render_empty_state(reports_dir)
        _render_session_history()
        return

    # =====================================================================
    # Summary
    # =====================================================================
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("报告总数", len(reports))
    with c2:
        newest = time.strftime("%m/%d %H:%M", time.localtime(reports[0].stat().st_mtime))
        st.metric("最新报告", newest)
    with c3:
        total_size = sum(p.stat().st_size for p in reports)
        st.metric("总大小", f"{total_size / 1024:.0f} KB")
    with c4:
        if st.button("刷新列表", use_container_width=True):
            st.rerun()

    st.markdown("---")

    # =====================================================================
    # Search and sort
    # =====================================================================
    sr1, sr2, sr3 = st.columns([3, 1, 1])
    with sr1:
        search = st.text_input("搜索", placeholder="按时间 / 数据集 / 预设筛选...", key="hist_search")
    with sr2:
        sort_by = st.selectbox("排序", ["时间 (最新)", "F1 (最高)", "样本数 (最多)"], key="hist_sort")
    with sr3:
        compare_mode = st.checkbox("对比两份报告", key="hist_compare")

    # =====================================================================
    # Compare mode
    # =====================================================================
    if compare_mode and len(reports) >= 2:
        sel = st.columns(2)
        with sel[0]:
            idx_a = st.selectbox("报告 A", range(len(reports)),
                                 format_func=lambda i: reports[i].name, key="cmp_a")
        with sel[1]:
            idx_b = st.selectbox("报告 B", range(len(reports)),
                                 format_func=lambda i: reports[i].name,
                                 index=min(1, len(reports) - 1), key="cmp_b")
        if idx_a != idx_b:
            _render_compare(reports[idx_a], reports[idx_b])
        st.markdown("---")

    # =====================================================================
    # Load and filter
    # =====================================================================
    report_data = []
    for path in reports:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            report_data.append((path, data))
        except Exception:
            continue

    if search:
        sl = search.lower()
        report_data = [
            (p, d) for p, d in report_data
            if sl in d.get("timestamp", "").lower()
            or sl in d.get("dataset", "").lower()
            or sl in d.get("preset", "").lower()
        ]

    if sort_by == "F1 (最高)":
        report_data.sort(key=lambda x: x[1].get("metrics", {}).get("F1", 0), reverse=True)
    elif sort_by == "样本数 (最多)":
        report_data.sort(key=lambda x: x[1].get("sample_count", 0), reverse=True)

    if not report_data:
        st.info("无匹配的报告")
        _render_session_history()
        return

    # =====================================================================
    # Report cards
    # =====================================================================
    for i in range(0, len(report_data), 2):
        cols = st.columns(2)
        for j, col in enumerate(cols):
            idx = i + j
            if idx >= len(report_data):
                break
            path, data = report_data[idx]
            with col:
                _render_report_card(path, data, idx)


def _render_report_card(path: Path, data: dict, idx: int) -> None:
    ts = data.get("timestamp", path.stem)
    ds = data.get("dataset", "?")
    preset = data.get("preset", "?")
    metrics = data.get("metrics", {})
    n = data.get("sample_count", len(data.get("results", [])))
    results = data.get("results", [])

    f1 = metrics.get("F1", 0)
    prec = metrics.get("Precision", 0)
    rec = metrics.get("Recall", 0)

    with st.container(border=True):
        hc1, hc2 = st.columns([3, 1])
        with hc1:
            st.markdown(f"**{ts}**")
            st.caption(f"数据集: {ds}  |  预设: {preset.upper()}  |  {n} 样本")
        with hc2:
            st.download_button(
                "下载", data=json.dumps(data, indent=2, ensure_ascii=False),
                file_name=path.name, mime="application/json",
                key=f"dl_{idx}", use_container_width=True,
            )

        if metrics:
            mc1, mc2, mc3 = st.columns(3)
            with mc1:
                st.metric("F1", f"{f1:.4f}")
            with mc2:
                st.metric("精确率", f"{prec:.4f}")
            with mc3:
                st.metric("召回率", f"{rec:.4f}")

        with st.expander("详情"):
            if metrics:
                st.markdown("##### 评测指标")
                render_metrics(metrics)
                render_confusion(
                    metrics.get("TP", 0), metrics.get("FP", 0),
                    metrics.get("FN", 0), metrics.get("TN", 0),
                )

            if results:
                st.markdown("##### 结果明细")
                import pandas as pd
                df = pd.DataFrame([{
                    "函数": r.get("function_name", "?")[:30],
                    "真实标签": "有漏洞" if r.get("has_vulnerability") else "安全",
                    "预测结果": "有漏洞" if r.get("predicted_vuln") else "安全",
                    "置信度": r.get("confidence", 0),
                    "方法": r.get("method", "?"),
                    "正确": "是" if r.get("correct") else "否",
                } for r in results])
                st.dataframe(df, use_container_width=True, hide_index=True,
                             height=min(400, 35 * len(results) + 38))

            if st.button("删除此报告", key=f"del_{idx}", type="secondary"):
                os.remove(path)
                st.success(f"已删除: {path.name}")
                st.rerun()


def _render_compare(path_a: Path, path_b: Path) -> None:
    import pandas as pd

    try:
        data_a = json.loads(path_a.read_text(encoding="utf-8"))
        data_b = json.loads(path_b.read_text(encoding="utf-8"))
    except Exception:
        st.error("读取报告失败")
        return

    st.markdown("#### 报告对比")
    ma, mb = data_a.get("metrics", {}), data_b.get("metrics", {})

    col_a, col_b = st.columns(2)
    with col_a:
        st.caption(f"A: {data_a.get('preset','?')} on {data_a.get('dataset','?')}")
        if ma:
            render_metrics(ma)
    with col_b:
        st.caption(f"B: {data_b.get('preset','?')} on {data_b.get('dataset','?')}")
        if mb:
            render_metrics(mb)

    if ma and mb:
        delta_df = pd.DataFrame([{
            "指标": m,
            "A": round(ma.get(m, 0), 4),
            "B": round(mb.get(m, 0), 4),
            "差值": round(ma.get(m, 0) - mb.get(m, 0), 4),
        } for m in ["F1", "Precision", "Recall", "FPR", "TP", "FP", "FN", "TN"]])
        st.dataframe(delta_df, use_container_width=True, hide_index=True)


def _render_empty_state(reports_dir: Path) -> None:
    st.info("暂无保存的报告")
    st.markdown("""
    ### 如何生成报告

    1. 进入 **批量评测** 页面
    2. 选择数据集和管道预设
    3. 点击 **开始评测**
    4. 评测完成后在结果底部保存报告

    报告保存在 `reports/eval_*.json`
    """)
    st.caption(f"报告目录: `{reports_dir}`")


def _render_session_history() -> None:
    if not st.session_state.get("scan_history"):
        return
    st.markdown("---")
    st.markdown("#### 本次会话扫描记录")
    for item in reversed(st.session_state.scan_history):
        st.caption(
            f"[{item['timestamp']}] 语言={item['language']}  |  "
            f"预设={item['preset']}  |  判定={item['verdict']}  |  "
            f"置信度={item['confidence']:.2f}  |  {item['elapsed']}s  |  "
            f"代码: `{item['code'][:60]}...`"
        )
