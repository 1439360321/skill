"""批量评测页 -- 数据集 -> 管道 -> 指标仪表板."""
from __future__ import annotations

import json
import re
import sys
import time
import random
from pathlib import Path

import streamlit as st

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT.parent))

from app.components.llm_utils import get_llm_client
from app.components.metrics_card import render_metrics, render_confusion

DATASETS = {
    "BigVul (100 样本)": {"file": "bigvul_test_set.json", "fmt": "json"},
    "Juliet (100 样本)": {"file": "juliet_test_set.json", "fmt": "json"},
    "D2A (100 样本)":    {"file": "d2a_test_set.json", "fmt": "json"},
}

PRESET_LABELS = {
    "v4": "v4 工具感知链 (推荐)", "v1": "v1 IRIS Agent 链",
    "v2": "v2 多温度投票", "v3": "v3 单次调用",
}


def render() -> None:
    st.title("批量评测")
    st.caption("在数据集上运行管道，计算 Precision / Recall / F1 / FPR")

    # =====================================================================
    # Control bar
    # =====================================================================
    with st.container(border=True):
        c1, c2, c3, c4, c5 = st.columns([2, 1, 2, 1, 1])

        quick_ds = st.session_state.pop("eval_quick_dataset", None)
        quick_preset = st.session_state.pop("eval_quick_preset", None)
        quick_n = st.session_state.pop("eval_quick_n", None)

        with c1:
            ds_index = list(DATASETS.keys()).index(quick_ds) if quick_ds in DATASETS else 0
            ds_label = st.selectbox("数据集", list(DATASETS.keys()), index=ds_index, key="eval_dataset")
        with c2:
            n_total = st.slider("样本数", 10, 200, quick_n if quick_n else 30, 5, key="eval_count")
        with c3:
            preset_idx = 0
            if quick_preset and quick_preset in ["v4", "v1", "v2", "v3"]:
                preset_idx = ["v4", "v1", "v2", "v3"].index(quick_preset)
            preset = st.selectbox(
                "管道预设", ["v4", "v1", "v2", "v3"],
                format_func=lambda p: PRESET_LABELS[p],
                index=preset_idx, key="eval_preset",
            )
        with c4:
            compare = st.checkbox("对比模式", key="eval_compare")
        with c5:
            st.caption("")
            start_btn = st.button("开始评测", type="primary", use_container_width=True, key="eval_start")

        preset_b = "v1"
        if compare:
            preset_b = st.selectbox("第二预设", ["v1", "v2", "v3", "v4"], index=0, key="eval_preset_b")

    # =====================================================================
    # Load dataset
    # =====================================================================
    data_dir = _ROOT / "data"
    ds_info = DATASETS[ds_label]
    ds_path = data_dir / ds_info["file"]

    if not ds_path.exists():
        st.error(f"数据集文件不存在: {ds_path}")
        st.stop()

    with st.spinner("加载数据集中..."):
        samples = _load_dataset(ds_path, ds_info["fmt"])

    if not samples:
        st.error("数据集为空")
        st.stop()

    if len(samples) > n_total:
        vuln = [s for s in samples if s.get("has_vulnerability")]
        safe = [s for s in samples if not s.get("has_vulnerability")]
        half = n_total // 2
        random.seed(42)
        sampled_v = random.sample(vuln, min(half, len(vuln)))
        sampled_s = random.sample(safe, min(n_total - len(sampled_v), len(safe)))
        samples = sampled_v + sampled_s
        random.shuffle(samples)

    n_vuln = sum(1 for s in samples if s.get("has_vulnerability"))
    n_safe = len(samples) - n_vuln
    ds_short = ds_label.split()[0]

    st.info(
        f"{ds_short}: {len(samples)} 样本 ({n_vuln} 有漏洞 / {n_safe} 安全)  |  "
        f"预设: {preset}" + (f" vs {preset_b}" if compare else "")
    )

    # =====================================================================
    # Run evaluation
    # =====================================================================
    if start_btn:
        st.session_state._eval_compare = False
        if compare:
            _run_compare(samples, preset, preset_b, ds_short)
            st.session_state._eval_compare = True
        else:
            _run_eval(samples, preset, ds_short)

    # --- results rendered OUTSIDE the if-block so they survive reruns ---
    eval_data = st.session_state.get("_eval_data")
    if eval_data:
        _display_results(
            eval_data["metrics"], eval_data["results"],
            eval_data["preset"], eval_data["ds_name"],
        )
        if st.session_state.get("_eval_compare"):
            _display_compare_results(eval_data)
        # save button — outside the run block, so it works on rerun
        _render_save_section(eval_data)


# ===========================================================================
# Data loading
# ===========================================================================

def _load_dataset(path: Path, fmt: str) -> list[dict]:
    import csv

    if fmt == "csv":
        csv.field_size_limit(sys.maxsize)
        out = []
        with open(path, encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                code = row.get("code", row.get("func", "")).strip()
                if not code:
                    continue
                out.append({
                    "code": code,
                    "has_vulnerability": int(row.get("target", "0")) == 1,
                    "file": row.get("project", row.get("file", "?")),
                    "function_name": row.get("func_name", row.get("function_name", "unknown")),
                })
        return out

    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    out = []
    for i, item in enumerate(raw):
        code = item.get("code") or item.get("func") or ""
        if not code:
            continue
        fn = item.get("function_name") or _extract_fn(code, item.get("file", f"s{i}"))
        out.append({
            "code": code,
            "has_vulnerability": bool(item.get("has_vulnerability", False)),
            "file": item.get("file", "?"),
            "function_name": fn,
        })
    return out


def _extract_fn(code: str, fallback: str = "unknown") -> str:
    """Extract function name from C/C++/Python source when dataset lacks it."""
    # Try C/C++ function definition at line start (avoid matching calls inside bodies)
    m = re.search(
        r'(?:^|\n)\s*(?:static\s+)?'
        r'(?:void|int|char|float|double|long|short|unsigned|size_t|ssize_t'
        r'|uint\w*|int\w*|bool|wchar_t|struct\s+\w+|enum\s+\w+'
        r'|SSL\s*\*|BIGNUM\s*\*|BIO\s*\*|EVP_PKEY\s*\*'
        r'|AVFormatContext\s*\*|APR_DECLARE\S*\s*|apr_\w+\s*\*?'
        r')\s+\**\s*(\w+)\s*\(', code, re.MULTILINE,
    )
    if m:
        return m.group(1)
    # Try Python:  def name ( params ) :
    m = re.search(r'def\s+(\w+)\s*\(', code)
    if m:
        return m.group(1)
    return fallback


# ===========================================================================
# Single sample runner
# ===========================================================================

def _run_one_sample(sample: dict, client, params: dict, slicer) -> dict:
    code = sample["code"]
    gt_vuln = sample.get("has_vulnerability", False)
    fn = sample.get("function_name", "unknown")

    wrap_c = (
        "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
        "#include <unistd.h>\n#include <fcntl.h>\n\n" + code
    )
    slices = slicer.slice_code(wrap_c, "c")

    if not slices:
        return {
            "file": sample.get("file", ""), "function_name": fn,
            "has_vulnerability": gt_vuln, "predicted_vuln": False,
            "confidence": 0.0, "method": "空切片", "correct": not gt_vuln,
        }

    sl = dict(slices[0])
    sl["language"] = "c"
    sl["_file_code"] = code
    sl["code_patterns"] = sl.get("code_patterns", [])
    sl["slicer_func_name"] = sl.get("function_name", "?")

    from src.llm.pipeline.orchestrator import run_pipeline

    try:
        pipe_result = run_pipeline(sl, client, params)
    except Exception as e:
        return {
            "file": sample.get("file", ""), "function_name": fn,
            "has_vulnerability": gt_vuln, "predicted_vuln": False,
            "confidence": 0.0, "method": "错误", "correct": not gt_vuln,
            "error": str(e)[:80],
        }

    pred_vuln = pipe_result.get("final_verdict") == "vuln"
    return {
        "file": sample["file"], "function_name": fn,
        "has_vulnerability": gt_vuln, "predicted_vuln": pred_vuln,
        "confidence": pipe_result.get("final_confidence", 0),
        "method": pipe_result.get("final_method", "?"),
        "correct": pred_vuln == gt_vuln,
    }


# ===========================================================================
# Single preset evaluation
# ===========================================================================

def _run_eval(samples: list[dict], preset: str, ds_name: str) -> None:
    from src.scanner.code_slicer import CodeSlicer
    from src.llm.pipeline.orchestrator import get_params
    from src.evaluation.evaluator import Evaluator

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

    params = get_params(preset)
    slicer = CodeSlicer()
    results: list[dict] = []
    total = len(samples)
    errors = 0

    progress = st.progress(0, text="准备中...")
    t0 = time.time()

    for i, sample in enumerate(samples):
        r = _run_one_sample(sample, client, params, slicer)
        if r.get("error"):
            errors += 1
        results.append(r)

        elapsed = time.time() - t0
        n_correct = sum(1 for r in results if r.get("correct"))
        eta = (elapsed / (i + 1)) * (total - i - 1) if i > 0 else 0
        progress.progress(
            (i + 1) / total,
            text=f"{i+1}/{total}  |  正确={n_correct}  |  错误={errors}  |  ETA {eta:.0f}s",
        )

    progress.empty()
    elapsed = time.time() - t0

    predictions = [{
        "file": r["file"], "function_name": r["function_name"],
        "has_vulnerability": r["predicted_vuln"],
    } for r in results]
    ground_truth = [{
        "file": s["file"], "function_name": s["function_name"],
        "has_vulnerability": s["has_vulnerability"],
    } for s in samples]
    ev = Evaluator(ground_truth)
    metrics = ev.evaluate(predictions)

    st.success(f"评测完成: {total} 样本 / {elapsed:.0f}s / {elapsed/total:.1f}s 每样本 / {errors} 错误")
    st.session_state._eval_data = {
        "metrics": metrics, "results": results, "preset": preset, "ds_name": ds_name,
    }


# ===========================================================================
# Dual preset comparison
# ===========================================================================

def _run_compare(samples: list[dict], preset_a: str, preset_b: str, ds_name: str) -> None:
    from src.scanner.code_slicer import CodeSlicer
    from src.llm.pipeline.orchestrator import get_params
    from src.evaluation.evaluator import Evaluator

    client = get_llm_client()
    if client is None:
        st.error("请先在设置页配置 LLM 连接并填入 API Key")
        return
    try:
        if not client.check_health():
            st.error("LLM API 不可用")
            return
    except Exception as e:
        st.error(f"连接失败: {e}")
        return

    slicer = CodeSlicer()
    total = len(samples)
    progress = st.progress(0, text="对比评测中...")
    t0 = time.time()

    results_a, results_b = [], []
    for i, sample in enumerate(samples):
        ra = _run_one_sample(sample, client, get_params(preset_a), slicer)
        rb = _run_one_sample(sample, client, get_params(preset_b), slicer)
        results_a.append(ra)
        results_b.append(rb)
        progress.progress((i + 1) / total, text=f"{i+1}/{total}")

    progress.empty()
    elapsed = time.time() - t0

    ground_truth = [{
        "file": s["file"], "function_name": s["function_name"],
        "has_vulnerability": s["has_vulnerability"],
    } for s in samples]

    preds_a = [{
        "file": r["file"], "function_name": r["function_name"],
        "has_vulnerability": r["predicted_vuln"],
    } for r in results_a]
    preds_b = [{
        "file": r["file"], "function_name": r["function_name"],
        "has_vulnerability": r["predicted_vuln"],
    } for r in results_b]

    ev = Evaluator(ground_truth)
    metrics_a = ev.evaluate(preds_a)
    metrics_b = ev.evaluate(preds_b)

    st.success(f"对比完成: {total} 样本 / {elapsed:.0f}s")
    st.session_state._eval_data = {
        "metrics": metrics_a, "results": results_a, "preset": preset_a, "ds_name": ds_name,
        "compare": True,
        "metrics_b": metrics_b, "results_b": results_b, "preset_b": preset_b,
        "total": total,
    }


# ===========================================================================
# Results display
# ===========================================================================

def _display_results(metrics: dict, results: list[dict], preset: str, ds_name: str) -> None:
    tp, fp, fn_val, tn = metrics["TP"], metrics["FP"], metrics["FN"], metrics["TN"]

    st.markdown("---")
    st.markdown("### 评测指标")
    render_metrics(metrics)

    with st.expander("混淆矩阵", expanded=False):
        render_confusion(tp, fp, fn_val, tn)

    errors_list = [r for r in results if r.get("error")]
    empty_slices = sum(1 for r in results if r.get("method") == "空切片")
    if errors_list or empty_slices:
        with st.expander(f"详情: {len(errors_list)} 错误, {empty_slices} 空切片", expanded=False):
            for e in errors_list:
                st.caption(f"{e.get('function_name', '?')}: {e.get('error', '?')}")

    st.markdown("---")
    st.markdown("### 逐样本结果")

    import pandas as pd
    df = pd.DataFrame(results)

    col_a, col_b, col_c = st.columns([2, 1, 1])
    with col_a:
        filt = st.selectbox("过滤", ["全部", "正确", "错误", "FN (漏报)", "FP (误报)"], key="eval_filter")
    with col_b:
        if filt == "正确":
            filt_df = df[df["correct"] == True]
        elif filt == "错误":
            filt_df = df[df["correct"] == False]
        elif filt == "FN (漏报)":
            filt_df = df[(df["has_vulnerability"] == True) & (df["correct"] == False)]
        elif filt == "FP (误报)":
            filt_df = df[(df["has_vulnerability"] == False) & (df["correct"] == False)]
        else:
            filt_df = df
        st.caption(f"{len(filt_df)} 条结果")
    with col_c:
        n_show = st.number_input("显示行数", 10, 500, 50, 10, key="eval_show")

    display_cols = [
        "file", "function_name", "has_vulnerability", "predicted_vuln",
        "confidence", "method", "correct",
    ]
    st.dataframe(
        filt_df[display_cols].head(n_show),
        use_container_width=True, hide_index=True,
    )


def _render_save_section(eval_data: dict) -> None:
    """渲染保存按钮 — 独立于评测运行流程，数据从 session_state 读取。"""
    results = eval_data["results"]
    metrics = eval_data["metrics"]
    preset = eval_data["preset"]
    ds_name = eval_data["ds_name"]

    with st.expander("保存报告", expanded=False):
        c_btn, _ = st.columns([1, 3])
        with c_btn:
            if st.button("保存到 reports/", key="save_eval", use_container_width=True):
                reports_dir = _ROOT / "reports"
                reports_dir.mkdir(parents=True, exist_ok=True)
                ts = time.strftime("%Y-%m-%d_%H-%M-%S")
                path = reports_dir / f"eval_{ds_name}_{preset}_{ts}.json"
                data = {
                    "timestamp": ts, "dataset": ds_name, "preset": preset,
                    "sample_count": len(results), "metrics": metrics,
                    "results": [{
                        k: v for k, v in r.items() if not k.startswith("_")
                    } for r in results],
                }
                path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
                st.success(f"已保存: {path.name}")


def _display_compare_results(eval_data: dict) -> None:
    """渲染对比模式的结果。"""
    import pandas as pd

    preset_a = eval_data["preset"]
    preset_b = eval_data["preset_b"]
    metrics_a = eval_data["metrics"]
    metrics_b = eval_data["metrics_b"]
    results_a = eval_data["results"]
    results_b = eval_data["results_b"]
    total = eval_data["total"]

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader(f"预设: {preset_a}")
        render_metrics(metrics_a)
    with col_b:
        st.subheader(f"预设: {preset_b}")
        render_metrics(metrics_b)

    st.markdown("---")
    st.subheader("横向对比")
    delta_df = pd.DataFrame([{
        "指标": m,
        f"{preset_a}": metrics_a.get(m, 0),
        f"{preset_b}": metrics_b.get(m, 0),
        "差值": round(metrics_a.get(m, 0) - metrics_b.get(m, 0), 4),
    } for m in ["F1", "Precision", "Recall", "FPR", "TP", "FP", "FN", "TN"]])
    st.dataframe(delta_df, use_container_width=True, hide_index=True)

    agree = sum(1 for ra, rb in zip(results_a, results_b)
                if ra.get("predicted_vuln") == rb.get("predicted_vuln"))
    st.caption(f"两个预设一致率: {agree}/{total} = {agree/total:.1%}")
