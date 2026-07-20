"""Overnight evaluation — 100-sample BigVul ablation + self-test.

Uses unique _sample_id matching to avoid key collision issues.
"""
import json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from src.scanner.code_slicer import CodeSlicer
from src.llm.llm_first_detector import (
    LLMFirstDetector, static_decision, extract_structured_context, agent1_screen
)
from src.utils.file_utils import find_source_files
from src.utils.logger import setup_logger
logger = setup_logger()

detector = LLMFirstDetector()
client = detector.client
if not client.check_health():
    logger.error("LLM not available"); sys.exit(1)

from src.config import Config
MODEL = Config()._data.get('llm', {}).get('model', '?')
logger.info(f"Model: {MODEL}")
t_start = time.time()

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# =========================================================================
# Helpers
# =========================================================================
def load_bigvul(path):
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    for i, s in enumerate(raw):
        s["_sample_id"] = f"bv_{i}"
    return raw

def slice_bigvul(samples):
    slicer = CodeSlicer()
    slices = []
    for s in samples:
        code = s.get("code", ""); sid = s["_sample_id"]
        sls = slicer.slice_code(code, "c")
        if not sls:
            slices.append({"_sample_id": sid, "has_vulnerability": False, "_no_slice": True})
            continue
        for sl in sls:
            sl["_sample_id"] = sid; sl["language"] = "c"
            sl["_file_code"] = code  # keep func_code from CodeSlicer
            slices.append(sl)
    return slices

def eval_by_id(samples, results):
    """Match by _sample_id, merge multi-slice: any vuln -> vuln."""
    tp = fp = fn = tn = 0
    gt_dict = {s["_sample_id"]: s.get("has_vulnerability", False) for s in samples}
    pred_dict = {}
    for r in results:
        sid = r["_sample_id"]
        pred_dict[sid] = pred_dict.get(sid, False) or r.get("has_vulnerability", False)
    for sid in gt_dict:
        gt, pred = gt_dict[sid], pred_dict.get(sid, False)
        if gt and pred: tp += 1
        elif not gt and pred: fp += 1
        elif gt and not pred: fn += 1
        else: tn += 1
    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"F1": round(f1,4), "Precision": round(p,4), "Recall": round(r,4),
            "FPR": round(fpr,4), "TP": tp, "FP": fp, "FN": fn, "TN": tn}

def _make_sample_id(file: str, function_name: str) -> str:
    """Stable identity from (file_basename, function_name).

    Convention: ``{Path(file).name}#{function_name}``
    Both GT entries and scanned slices use this same convention independently,
    so the evaluator can match them by key lookup without any GT-aware logic.
    """
    return f"{Path(file).name}#{function_name}"

def load_self_test(path):
    with open(path, encoding="utf-8") as f:
        gt = json.load(f)
    for s in gt:
        s["_sample_id"] = _make_sample_id(s.get("file", ""), s.get("function_name", ""))
    return gt

def slice_self_test():
    """Produce slices with self-contained identity — no GT lookup.

    Each slice carries _sample_id derived purely from (source file basename,
    function name).  The evaluator later matches against GT entries that
    independently compute the same identity from their own file/function fields.
    """
    slicer = CodeSlicer()
    slices = []
    for fp in find_source_files("examples", ["c", "python"]):
        ext = fp.suffix.lower()
        lang = "c" if ext in (".c", ".h") else "python" if ext == ".py" else None
        if not lang:
            continue
        code = fp.read_text(encoding="utf-8-sig", errors="ignore")
        sls = slicer.slice_code(code, lang)
        if not sls:
            continue
        for sl in sls:
            fn = sl.get("function_name", "?")
            sl["_sample_id"] = _make_sample_id(fp.name, fn)
            sl["language"] = lang
            sl["_file_code"] = code
            slices.append(sl)
    return slices

# =========================================================================
# 1. BigVul ablation
# =========================================================================
raw = load_bigvul(str(DATA_DIR / "bigvul_test_set.json"))
vn = sum(1 for s in raw if s["has_vulnerability"])
print(f"BigVul: {len(raw)} samples ({vn} vuln / {len(raw)-vn} safe)")

bv_slices = slice_bigvul(raw)
print(f"Slices: {len(bv_slices)}")

# A: Static only
res_a = []
for sl in bv_slices:
    if sl.get("_no_slice"):
        res_a.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False})
    else:
        res_a.append({"_sample_id": sl["_sample_id"], "has_vulnerability": sl.get("risk_level") != "low"})
ma = eval_by_id(raw, res_a)
print(f"\nA (Static only):      F1={ma['F1']:.4f} P={ma['Precision']:.4f} R={ma['Recall']:.4f} FPR={ma['FPR']:.4f}  TP/FP/FN/TN={ma['TP']}/{ma['FP']}/{ma['FN']}/{ma['TN']}")

# B: +CWE prompt
res_b = []
calls_b = 0
for sl in bv_slices:
    if sl.get("_no_slice"):
        res_b.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False}); continue
    dec = static_decision(sl)
    if dec == "vuln":
        res_b.append({"_sample_id": sl["_sample_id"], "has_vulnerability": True})
    elif dec == "safe":
        res_b.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False})
    else:
        ctx = extract_structured_context(sl)
        ctx["code_keyline"] = sl.get("code", "")[:1500]; ctx["code"] = sl.get("code", "")
        a1 = agent1_screen(client, ctx); calls_b += 1
        res_b.append({"_sample_id": sl["_sample_id"], "has_vulnerability": a1.get("verdict") == "suspicious" if a1 else False})
mb = eval_by_id(raw, res_b)
print(f"B (+CWE prompt):      F1={mb['F1']:.4f} P={mb['Precision']:.4f} R={mb['Recall']:.4f} FPR={mb['FPR']:.4f}  TP/FP/FN/TN={mb['TP']}/{mb['FP']}/{mb['FN']}/{mb['TN']}  calls={calls_b}")

# C: Full pipeline
res_c = []
calls_c = 0
for sl in bv_slices:
    if sl.get("_no_slice"):
        res_c.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False}); continue
    r = detector.detect(sl); calls_c += detector.llm_calls; detector.llm_calls = 0
    res_c.append({"_sample_id": sl["_sample_id"], "has_vulnerability": r["final_verdict"] == "vuln"})
mc = eval_by_id(raw, res_c)
print(f"C (Full pipeline):    F1={mc['F1']:.4f} P={mc['Precision']:.4f} R={mc['Recall']:.4f} FPR={mc['FPR']:.4f}  TP/FP/FN/TN={mc['TP']}/{mc['FP']}/{mc['FN']}/{mc['TN']}  calls={calls_c}")

# =========================================================================
# 2. Self-test ablation
# =========================================================================
gt_self = load_self_test(str(DATA_DIR / "test_set.json"))
self_slices = slice_self_test()
print(f"\nSelf-test: {len(gt_self)} GT, {len(self_slices)} slices")

# A: Static only
res_sa = []
for sl in self_slices:
    res_sa.append({"_sample_id": sl["_sample_id"], "has_vulnerability": sl.get("risk_level") == "high"})
msa = eval_by_id(gt_self, res_sa)
print(f"A (Static only):      F1={msa['F1']:.4f} P={msa['Precision']:.4f} R={msa['Recall']:.4f} FPR={msa['FPR']:.4f}  TP/FP/FN/TN={msa['TP']}/{msa['FP']}/{msa['FN']}/{msa['TN']}")

# B: +CWE prompt
res_sb = []
calls_sb = 0
for sl in self_slices:
    dec = static_decision(sl)
    if dec == "vuln":
        res_sb.append({"_sample_id": sl["_sample_id"], "has_vulnerability": True})
    elif dec == "safe":
        res_sb.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False})
    else:
        ctx = extract_structured_context(sl)
        ctx["code_keyline"] = sl.get("code", "")[:1500]; ctx["code"] = sl.get("code", "")
        a1 = agent1_screen(client, ctx); calls_sb += 1
        res_sb.append({"_sample_id": sl["_sample_id"], "has_vulnerability": a1.get("verdict") == "suspicious" if a1 else False})
msb = eval_by_id(gt_self, res_sb)
print(f"B (+CWE prompt):      F1={msb['F1']:.4f} P={msb['Precision']:.4f} R={msb['Recall']:.4f} FPR={msb['FPR']:.4f}  TP/FP/FN/TN={msb['TP']}/{msb['FP']}/{msb['FN']}/{msb['TN']}  calls={calls_sb}")

# C: Full pipeline
res_sc = []
calls_sc = 0
for sl in self_slices:
    r = detector.detect(sl); calls_sc += detector.llm_calls; detector.llm_calls = 0
    res_sc.append({"_sample_id": sl["_sample_id"], "has_vulnerability": r["final_verdict"] == "vuln"})
msc = eval_by_id(gt_self, res_sc)
print(f"C (Full pipeline):    F1={msc['F1']:.4f} P={msc['Precision']:.4f} R={msc['Recall']:.4f} FPR={msc['FPR']:.4f}  TP/FP/FN/TN={msc['TP']}/{msc['FP']}/{msc['FN']}/{msc['TN']}  calls={calls_sc}")

# =========================================================================
# 3. PrimeVul (50 samples: 20 vuln + 30 safe) — with CodeQL integration
# =========================================================================
import csv, re
csv.field_size_limit(sys.maxsize)
CSV_PATH = DATA_DIR / "primevul_test.csv"
if CSV_PATH.exists():
    MAX_PV_V, MAX_PV_S = 20, 30
    pv_vuln, pv_safe = [], []
    with open(CSV_PATH, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            code = row.get("code", "").strip(); target = int(row.get("target", "0"))
            if not code: continue
            if target == 1 and len(pv_vuln) < MAX_PV_V: pv_vuln.append((code, target))
            elif target == 0 and len(pv_safe) < MAX_PV_S: pv_safe.append((code, target))
            if len(pv_vuln) >= MAX_PV_V and len(pv_safe) >= MAX_PV_S: break
    pv_samples = pv_vuln + pv_safe
    pv_gt = []
    for i, (code, target) in enumerate(pv_samples):
        pv_gt.append({"_sample_id": f"pv_{i}", "has_vulnerability": target == 1})

    def wrap_c(code):
        return "\n".join(["#include <stdio.h>", "#include <stdlib.h>", "#include <string.h>",
                          "#include <unistd.h>", "#include <fcntl.h>"]) + "\n\n" + code

    # --- Run CodeQL batch on all wrapped samples ---
    from src.scanner.codeql_runner import run_codeql_batch
    pv_wrapped = [(wrap_c(code), "c") for code, _ in pv_samples]
    t_cql = time.time()
    pv_codeql_findings = run_codeql_batch(pv_wrapped)
    cql_sec = time.time() - t_cql
    cql_hits = sum(1 for f in pv_codeql_findings if f)
    print(f"CodeQL: {cql_hits}/{len(pv_samples)} samples with findings ({cql_sec:.0f}s)")

    pv_slicer = CodeSlicer()
    pv_slices = []
    for i, (code, target) in enumerate(pv_samples):
        sls = pv_slicer.slice_code(wrap_c(code), "c")
        if not sls:
            pv_slices.append({"_sample_id": f"pv_{i}", "has_vulnerability": False, "_no_slice": True})
            continue
        for sl in sls:
            sl["_sample_id"] = f"pv_{i}"; sl["language"] = "c"
            sl["_file_code"] = code
            sl["code_patterns"] = pv_codeql_findings[i]
            pv_slices.append(sl)

    vn_pv = sum(1 for s in pv_gt if s["has_vulnerability"])
    no_sink_pv = sum(1 for sl in pv_slices if not sl.get("_no_slice") and not sl.get("sink_type"))
    print(f"\nPrimeVul: {len(pv_gt)} samples ({vn_pv} vuln / {len(pv_gt)-vn_pv} safe)")
    print(f"Slices: {len(pv_slices)} (no_sink={no_sink_pv})")

    # A: Static only
    res_pa = []
    for sl in pv_slices:
        if sl.get("_no_slice"):
            res_pa.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False})
        else:
            res_pa.append({"_sample_id": sl["_sample_id"], "has_vulnerability": sl.get("risk_level") == "high"})
    mpa = eval_by_id(pv_gt, res_pa)
    print(f"A (Static only):      F1={mpa['F1']:.4f} P={mpa['Precision']:.4f} R={mpa['Recall']:.4f} FPR={mpa['FPR']:.4f}  TP/FP/FN/TN={mpa['TP']}/{mpa['FP']}/{mpa['FN']}/{mpa['TN']}")

    # B: +CWE prompt
    res_pb = []
    calls_pb = 0
    for sl in pv_slices:
        if sl.get("_no_slice"):
            res_pb.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False}); continue
        dec = static_decision(sl)
        if dec == "vuln":
            res_pb.append({"_sample_id": sl["_sample_id"], "has_vulnerability": True})
        elif dec == "safe":
            res_pb.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False})
        else:
            ctx = extract_structured_context(sl)
            ctx["code_keyline"] = sl.get("code", "")[:1500]; ctx["code"] = sl.get("code", "")
            a1 = agent1_screen(client, ctx); calls_pb += 1
            res_pb.append({"_sample_id": sl["_sample_id"], "has_vulnerability": a1.get("verdict") == "suspicious" if a1 else False})
    mpb = eval_by_id(pv_gt, res_pb)
    print(f"B (+CWE prompt):      F1={mpb['F1']:.4f} P={mpb['Precision']:.4f} R={mpb['Recall']:.4f} FPR={mpb['FPR']:.4f}  TP/FP/FN/TN={mpb['TP']}/{mpb['FP']}/{mpb['FN']}/{mpb['TN']}  calls={calls_pb}")

    # C: Full pipeline
    res_pc = []
    calls_pc = 0
    for sl in pv_slices:
        if sl.get("_no_slice"):
            res_pc.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False}); continue
        r = detector.detect(sl); calls_pc += detector.llm_calls; detector.llm_calls = 0
        res_pc.append({"_sample_id": sl["_sample_id"], "has_vulnerability": r["final_verdict"] == "vuln"})
    mpc = eval_by_id(pv_gt, res_pc)
    print(f"C (Full pipeline):    F1={mpc['F1']:.4f} P={mpc['Precision']:.4f} R={mpc['Recall']:.4f} FPR={mpc['FPR']:.4f}  TP/FP/FN/TN={mpc['TP']}/{mpc['FP']}/{mpc['FN']}/{mpc['TN']}  calls={calls_pc}")
else:
    pv_gt = []; mpa = mpb = mpc = {}
    calls_pb = calls_pc = 0

# =========================================================================
# Summary
# =========================================================================
total_llm = calls_b + calls_c + calls_sb + calls_sc + calls_pb + calls_pc
elapsed = time.time() - t_start
print(f"\n{'='*70}")
print(f"  Overnight Evaluation  |  {MODEL}  |  {(elapsed/60):.0f}min  |  {total_llm} LLM calls")
print(f"{'='*70}")
print(f"  {'Test / Stage':<30} {'F1':>8} {'P':>8} {'R':>8} {'FPR':>8}  {'TP/FP/FN/TN':>14}")
print(f"  {'-'*30} {'-'*8} {'-'*8} {'-'*8} {'-'*8}  {'-'*14}")
print(f"  {'BigVul A: Static only':<30} {ma['F1']:>8.4f} {ma['Precision']:>8.4f} {ma['Recall']:>8.4f} {ma['FPR']:>8.4f}  {ma['TP']}/{ma['FP']}/{ma['FN']}/{ma['TN']}")
print(f"  {'BigVul B: +CWE prompt':<30} {mb['F1']:>8.4f} {mb['Precision']:>8.4f} {mb['Recall']:>8.4f} {mb['FPR']:>8.4f}  {mb['TP']}/{mb['FP']}/{mb['FN']}/{mb['TN']}")
print(f"  {'BigVul C: +Multi-temp':<30} {mc['F1']:>8.4f} {mc['Precision']:>8.4f} {mc['Recall']:>8.4f} {mc['FPR']:>8.4f}  {mc['TP']}/{mc['FP']}/{mc['FN']}/{mc['TN']}")
print(f"  {'Self-test A: Static only':<30} {msa['F1']:>8.4f} {msa['Precision']:>8.4f} {msa['Recall']:>8.4f} {msa['FPR']:>8.4f}  {msa['TP']}/{msa['FP']}/{msa['FN']}/{msa['TN']}")
print(f"  {'Self-test B: +CWE prompt':<30} {msb['F1']:>8.4f} {msb['Precision']:>8.4f} {msb['Recall']:>8.4f} {msb['FPR']:>8.4f}  {msb['TP']}/{msb['FP']}/{msb['FN']}/{msb['TN']}")
print(f"  {'Self-test C: +Multi-temp':<30} {msc['F1']:>8.4f} {msc['Precision']:>8.4f} {msc['Recall']:>8.4f} {msc['FPR']:>8.4f}  {msc['TP']}/{msc['FP']}/{msc['FN']}/{msc['TN']}")
if CSV_PATH.exists():
    print(f"  {'PrimeVul A: Static only':<30} {mpa['F1']:>8.4f} {mpa['Precision']:>8.4f} {mpa['Recall']:>8.4f} {mpa['FPR']:>8.4f}  {mpa['TP']}/{mpa['FP']}/{mpa['FN']}/{mpa['TN']}")
    print(f"  {'PrimeVul B: +CWE prompt':<30} {mpb['F1']:>8.4f} {mpb['Precision']:>8.4f} {mpb['Recall']:>8.4f} {mpb['FPR']:>8.4f}  {mpb['TP']}/{mpb['FP']}/{mpb['FN']}/{mpb['TN']}")
    print(f"  {'PrimeVul C: +Multi-temp':<30} {mpc['F1']:>8.4f} {mpc['Precision']:>8.4f} {mpc['Recall']:>8.4f} {mpc['FPR']:>8.4f}  {mpc['TP']}/{mpc['FP']}/{mpc['FN']}/{mpc['TN']}")

Path("reports").mkdir(exist_ok=True)
report = {
    "model": MODEL, "elapsed_min": round(elapsed/60, 1),
    "bigvul_samples": len(raw),
    "bigvul_A_static": ma, "bigvul_B_cwe_prompt": mb, "bigvul_C_full_pipeline": mc,
    "self_test_A_static": msa, "self_test_B_cwe_prompt": msb, "self_test_C_full_pipeline": msc,
    "primevul_samples": len(pv_gt),
    "primevul_A_static": mpa if CSV_PATH.exists() else {},
    "primevul_B_cwe_prompt": mpb if CSV_PATH.exists() else {},
    "primevul_C_full_pipeline": mpc if CSV_PATH.exists() else {},
    "total_llm_calls": total_llm,
}
with open("reports/eval_overnight.json", "w") as f:
    json.dump(report, f, indent=2)
print(f"\nSaved: reports/eval_overnight.json")
print(f"Done at {time.strftime('%H:%M:%S')}")
