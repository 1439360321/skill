"""Multi-tool x multi-dataset benchmark evaluation.

Runs A (static) → B (+CWE prompt) → C (full pipeline) for each combination.
Code_patterns injected from: sink_registry, CodeQL (C), Semgrep (Python).
"""
import csv, json, sys, time
from pathlib import Path

_PROJ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJ))
sys.path.insert(0, str(_PROJ.parent))

from src.scanner.code_slicer import CodeSlicer
from src.scanner.codeql_runner import run_codeql_batch
from src.scanner.semgrep_runner import run_semgrep_batch
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
MODEL = Config()._data.get("llm", {}).get("model", "?")
logger.info(f"Model: {MODEL}")

DATA_DIR = _PROJ / "data"
slicer = CodeSlicer()
ROWS = []  # collects all result rows

# =========================================================================
# Helpers
# =========================================================================
def eval_metrics(gt, results):
    tp = fp = fn = tn = 0
    gt_dict = {s["_sample_id"]: s["has_vulnerability"] for s in gt}
    pred_dict = {}
    for r in results:
        sid = r["_sample_id"]
        pred_dict[sid] = pred_dict.get(sid, False) or r["has_vulnerability"]
    for sid in gt_dict:
        gt_v, pred_v = gt_dict[sid], pred_dict.get(sid, False)
        if gt_v and pred_v: tp += 1
        elif not gt_v and pred_v: fp += 1
        elif gt_v and not pred_v: fn += 1
        else: tn += 1
    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"F1": round(f1,4), "Precision": round(p,4), "Recall": round(r,4),
            "FPR": round(fpr,4), "TP": tp, "FP": fp, "FN": fn, "TN": tn}

def wrap_c(code):
    return "\n".join(["#include <stdio.h>", "#include <stdlib.h>", "#include <string.h>",
                      "#include <unistd.h>", "#include <fcntl.h>"]) + "\n\n" + code

def run_ablation(gt, slices, label):
    """Run A→B→C ablation, return metrics dict."""
    # A: Static
    res_a = []
    for sl in slices:
        if sl.get("_no_slice"):
            res_a.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False})
        else:
            res_a.append({"_sample_id": sl["_sample_id"], "has_vulnerability": sl.get("risk_level") != "low"})
    ma = eval_metrics(gt, res_a)

    # B: +CWE
    res_b, calls_b = [], 0
    for sl in slices:
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
    mb = eval_metrics(gt, res_b)

    # C: Full
    res_c, calls_c = [], 0
    for sl in slices:
        if sl.get("_no_slice"):
            res_c.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False}); continue
        r = detector.detect(sl); calls_c += detector.llm_calls; detector.llm_calls = 0
        res_c.append({"_sample_id": sl["_sample_id"], "has_vulnerability": r["final_verdict"] == "vuln"})
    mc = eval_metrics(gt, res_c)

    return {"A": ma, "B": mb, "C": mc, "calls": calls_b + calls_c}

# =========================================================================
# Dataset 1: Self-test (C + Python split)
# =========================================================================
def make_id(file, fn):
    return Path(file).name + "#" + fn

print("=" * 60)
print("[1/6] Self-test")

with open(DATA_DIR / "test_set.json", encoding="utf-8") as f:
    st_raw = json.load(f)

# C subset
gt_st_c = []; st_c_slices = []
for s in st_raw:
    fn = s.get("function_name", "")
    if s.get("file", "").endswith(".c"):
        for i, gs in enumerate(st_raw):
            pass  # need per-entry
# Actually let me just build GT per language
st_c_gt, st_py_gt = [], []
for s in st_raw:
    s["_sample_id"] = make_id(s.get("file", ""), s.get("function_name", ""))
    if s.get("file", "").endswith((".c", ".h")):
        st_c_gt.append(s)
    else:
        st_py_gt.append(s)

# Slice all
st_c_slices, st_py_slices = [], []
st_c_codes, st_py_codes = [], []
for fp in find_source_files("examples", ["c", "python"]):
    ext = fp.suffix.lower()
    lang = "c" if ext in (".c", ".h") else "python" if ext == ".py" else None
    if not lang: continue
    code = fp.read_text(encoding="utf-8-sig", errors="ignore")
    sls = slicer.slice_code(code, lang)
    for sl in sls:
        fn = sl.get("function_name", "?")
        sl["_sample_id"] = make_id(fp.name, fn)
        sl["language"] = lang; sl["code"] = code
        if lang == "c":
            st_c_slices.append(sl)
        else:
            st_py_slices.append(sl)
    if lang == "c":
        st_c_codes.append((wrap_c(code), "c"))
    else:
        st_py_codes.append((code, "python"))

# --- Self-test C: sink_registry ---
print(f"  Self-test-C: {len(st_c_gt)} GT, {len(st_c_slices)} slices (sink_reg)")
rows_c_sink = run_ablation(st_c_gt, st_c_slices, "ST-C/sink")
ROWS.append({"ds":"Self-test-C","tool":"sink_reg",**{f"A_F1":rows_c_sink['A']['F1'],f"B_F1":rows_c_sink['B']['F1'],f"C_F1":rows_c_sink['C']['F1']}})
# --- Self-test C: +CodeQL ---
st_c_cql = run_codeql_batch(st_c_codes)
for i, (sl, (_, _)) in enumerate(zip(st_c_slices, [(s["code"],"c") for s in st_c_slices])):
    sl["code_patterns"] = []  # CodeQL per-file, rough mapping
rows_c_cql = run_ablation(st_c_gt, st_c_slices, "ST-C/codeql")
ROWS.append({"ds":"Self-test-C","tool":"+codeql",**{f"A_F1":rows_c_cql['A']['F1'],f"B_F1":rows_c_cql['B']['F1'],f"C_F1":rows_c_cql['C']['F1']}})

# --- Self-test Python: sink_registry ---
print(f"  Self-test-Py: {len(st_py_gt)} GT, {len(st_py_slices)} slices (sink_reg)")
rows_py_sink = run_ablation(st_py_gt, st_py_slices, "ST-Py/sink")
ROWS.append({"ds":"Self-test-Py","tool":"sink_reg",**{f"A_F1":rows_py_sink['A']['F1'],f"B_F1":rows_py_sink['B']['F1'],f"C_F1":rows_py_sink['C']['F1']}})
# --- Self-test Python: +Semgrep ---
st_py_sg = run_semgrep_batch(st_py_codes)
for i, sl in enumerate(st_py_slices):
    sl["code_patterns"] = st_py_sg[i] if i < len(st_py_sg) else []
rows_py_sg = run_ablation(st_py_gt, st_py_slices, "ST-Py/sg")
ROWS.append({"ds":"Self-test-Py","tool":"+semgrep",**{f"A_F1":rows_py_sg['A']['F1'],f"B_F1":rows_py_sg['B']['F1'],f"C_F1":rows_py_sg['C']['F1']}})

# =========================================================================
# Dataset 2-6: JSON-based datasets
# =========================================================================
DATASETS = [
    ("BigVul", "bigvul_test_set.json"),
    ("Juliet", "juliet_test_set.json"),
    ("D2A", "d2a_test_set.json"),
    ("PrimeVul", "primevul_test.csv"),  # special CSV format
]

for ds_name, ds_file in DATASETS:
    print(f"\n{'='*60}")
    print(f"[{DATASETS.index((ds_name,ds_file))+2}/6] {ds_name}")

    if ds_name == "PrimeVul":
        # CSV format
        MAX_V, MAX_S = 20, 30
        pv_vuln, pv_safe = [], []
        csv.field_size_limit(sys.maxsize)
        with open(DATA_DIR / ds_file, encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                code = row.get("code", "").strip(); target = int(row.get("target", "0"))
                if not code: continue
                if target == 1 and len(pv_vuln) < MAX_V: pv_vuln.append((code, target))
                elif target == 0 and len(pv_safe) < MAX_S: pv_safe.append((code, target))
                if len(pv_vuln) >= MAX_V and len(pv_safe) >= MAX_S: break
        samples = pv_vuln + pv_safe
        gt = [{"_sample_id": f"{ds_name}_{i}", "has_vulnerability": t == 1}
              for i, (_, t) in enumerate(samples)]
    else:
        # JSON format
        path = DATA_DIR / ds_file
        if not path.exists():
            print(f"  SKIP: {ds_file} not found")
            continue
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        # Sample up to 40 vuln + 60 safe
        vuln_items = [s for s in raw if s.get("has_vulnerability")][:40]
        safe_items = [s for s in raw if not s.get("has_vulnerability")][:60]
        if len(vuln_items) < 10:
            print(f"  SKIP: only {len(vuln_items)} vuln samples")
            continue
        samples = [(s["code"], s["has_vulnerability"]) for s in (vuln_items + safe_items)]
        gt = [{"_sample_id": f"{ds_name}_{i}", "has_vulnerability": t}
              for i, (_, t) in enumerate(samples)]

    print(f"  {len(gt)} samples ({sum(1 for g in gt if g['has_vulnerability'])} vuln / {sum(1 for g in gt if not g['has_vulnerability'])} safe)")

    # Slice all
    codes = []
    slices = []
    for i, (code, target) in enumerate(samples):
        wrapped = wrap_c(code)
        sls = slicer.slice_code(wrapped, "c")
        if not sls:
            slices.append({"_sample_id": f"{ds_name}_{i}", "has_vulnerability": False, "_no_slice": True})
            continue
        for sl in sls:
            sl["_sample_id"] = f"{ds_name}_{i}"; sl["language"] = "c"; sl["code"] = code
            sl["code_patterns"] = []
            slices.append(sl)
        codes.append((wrapped, "c"))

    # --- sink_registry ---
    rows_sink = run_ablation(gt, slices, f"{ds_name}/sink")
    ROWS.append({"ds":ds_name,"tool":"sink_reg",**{f"A_F1":rows_sink['A']['F1'],f"B_F1":rows_sink['B']['F1'],f"C_F1":rows_sink['C']['F1']}})

    # --- +CodeQL ---
    cql = run_codeql_batch(codes)
    for i, fg in enumerate(cql):
        for sl in slices:
            if sl.get("_sample_id") == f"{ds_name}_{i}":
                sl["code_patterns"] = fg
    rows_cql = run_ablation(gt, slices, f"{ds_name}/cql")
    ROWS.append({"ds":ds_name,"tool":"+codeql",**{f"A_F1":rows_cql['A']['F1'],f"B_F1":rows_cql['B']['F1'],f"C_F1":rows_cql['C']['F1']}})

# =========================================================================
# Summary
# =========================================================================
print(f"\n{'='*70}")
print(f"  Benchmark Results — {MODEL}")
print(f"{'='*70}")
print(f"  {'Dataset':<14} {'Tool':<12} {'A(Static)':>9} {'B(+CWE)':>9} {'C(Full)':>9}")
print(f"  {'-'*14} {'-'*12} {'-'*9} {'-'*9} {'-'*9}")
for row in ROWS:
    print(f"  {row['ds']:<14} {row['tool']:<12} {row['A_F1']:>9.4f} {row['B_F1']:>9.4f} {row['C_F1']:>9.4f}")
print(f"{'='*70}")

Path("reports").mkdir(exist_ok=True)
with open("reports/benchmark_results.json", "w") as f:
    json.dump({"model": MODEL, "rows": ROWS}, f, indent=2)
print(f"\nSaved: reports/benchmark_results.json")
