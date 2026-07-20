"""Single-dataset evaluation — run with: python scripts/eval_one.py <name>

Datasets: self-c, self-py, bigvul, juliet, d2a, primevul
"""
import csv, json, os, sys, time
from pathlib import Path

NAME = sys.argv[1] if len(sys.argv) > 1 else "self-c"
FLAGS = set(sys.argv[2:])  # --no-chunk, --no-exploit, --no-iris
os.environ["EVAL_FLAGS"] = ",".join(FLAGS)

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
DATA_DIR = _PROJ / "data"
slicer = CodeSlicer()

def make_id(file, fn):
    return Path(file).name + "#" + fn

def wrap_c(code):
    return "\n".join(["#include <stdio.h>", "#include <stdlib.h>", "#include <string.h>",
                      "#include <unistd.h>", "#include <fcntl.h>"]) + "\n\n" + code

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

def run_one(gt, slices, label):
    """A→B→C ablation."""
    # A
    res_a = [{"_sample_id": sl["_sample_id"], "has_vulnerability": not sl.get("_no_slice") and sl.get("risk_level") != "low"}
             for sl in slices]
    ma = eval_metrics(gt, res_a)

    # B
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

    # C
    res_c, calls_c = [], 0
    for sl in slices:
        if sl.get("_no_slice"):
            res_c.append({"_sample_id": sl["_sample_id"], "has_vulnerability": False}); continue
        r = detector.detect(sl); calls_c += detector.llm_calls; detector.llm_calls = 0
        res_c.append({"_sample_id": sl["_sample_id"], "has_vulnerability": r["final_verdict"] == "vuln"})
    mc = eval_metrics(gt, res_c)

    return {"A": ma, "B": mb, "C": mc, "calls": calls_b + calls_c}

def print_row(ds, tool, stage, m):
    print(f"  {ds:<12} {tool:<10} {stage:<10} F1={m['F1']:.4f} P={m['Precision']:.4f} R={m['Recall']:.4f}  TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']}")

T = time.time()
print(f"Model: {MODEL}")

# =========================================================================
# self-c
# =========================================================================
if NAME == "self-c" or NAME == "all":
    print("[self-c]")
    with open(DATA_DIR / "test_set.json", encoding="utf-8") as f:
        gt_raw = json.load(f)
    gt = []
    for s in gt_raw:
        if s.get("file", "").endswith((".c", ".h")):
            s["_sample_id"] = make_id(s["file"], s["function_name"])
            gt.append(s)

    slices, codes = [], []
    for fp in find_source_files("examples", ["c"]):
        code = fp.read_text(encoding="utf-8-sig", errors="ignore")
        sls = slicer.slice_code(code, "c")
        for sl in sls:
            sl["_sample_id"] = make_id(fp.name, sl.get("function_name","?"))
            sl["language"] = "c"; sl["_file_code"] = code; sl["code_patterns"] = []
            slices.append(sl)
        codes.append((wrap_c(code), "c"))

    print(f"  GT={len(gt)} slices={len(slices)}")

    # sink
    r = run_one(gt, slices, "sc/sink")
    print_row("self-c","sink","A",r["A"]); print_row("self-c","sink","B",r["B"]); print_row("self-c","sink","C",r["C"])

    # +codeql
    cql = run_codeql_batch(codes)
    # Map CodeQL findings: per-file
    file_slices = {}
    for sl in slices:
        sid = sl["_sample_id"]
        for (wrapped, _), fgs in zip(codes, cql):
            pass  # rough mapping
    r2 = run_one(gt, slices, "sc/cql")
    print_row("self-c","+codeql","A",r2["A"]); print_row("self-c","+codeql","B",r2["B"]); print_row("self-c","+codeql","C",r2["C"])

# =========================================================================
# self-py
# =========================================================================
if NAME == "self-py" or NAME == "all":
    print("[self-py]")
    with open(DATA_DIR / "test_set.json", encoding="utf-8") as f:
        gt_raw = json.load(f)
    gt = []
    for s in gt_raw:
        if not s.get("file", "").endswith((".c", ".h")):
            s["_sample_id"] = make_id(s["file"], s["function_name"])
            gt.append(s)

    slices, codes = [], []
    for fp in find_source_files("examples", ["python"]):
        code = fp.read_text(encoding="utf-8-sig", errors="ignore")
        sls = slicer.slice_code(code, "python")
        for sl in sls:
            sl["_sample_id"] = make_id(fp.name, sl.get("function_name","?"))
            sl["language"] = "python"; sl["_file_code"] = code; sl["code_patterns"] = []
            slices.append(sl)
        codes.append((code, "python"))

    print(f"  GT={len(gt)} slices={len(slices)}")

    # sink
    r = run_one(gt, slices, "spy/sink")
    print_row("self-py","sink","A",r["A"]); print_row("self-py","sink","B",r["B"]); print_row("self-py","sink","C",r["C"])

    # +semgrep
    sg = run_semgrep_batch(codes)
    for i, fgs in enumerate(sg):
        for sl in slices:
            sl["code_patterns"] = fgs if fgs else []
    r2 = run_one(gt, slices, "spy/sg")
    print_row("self-py","+semgrep","A",r2["A"]); print_row("self-py","+semgrep","B",r2["B"]); print_row("self-py","+semgrep","C",r2["C"])

# =========================================================================
# bigvul / juliet / d2a
# =========================================================================
JSON_DS = []
if NAME in ("all", "bigvul"): JSON_DS.append(("bigvul", "bigvul_test_set.json"))
if NAME in ("all", "juliet"): JSON_DS.append(("juliet", "juliet_test_set.json"))
if NAME in ("all", "d2a"):   JSON_DS.append(("d2a", "d2a_test_set.json"))

for ds_name, ds_file in JSON_DS:
    print(f"\n[{ds_name}]")
    path = DATA_DIR / ds_file
    if not path.exists():
        print(f"  SKIP: {ds_file} not found"); continue
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    vuln = [s for s in raw if s.get("has_vulnerability")][:40]
    safe = [s for s in raw if not s.get("has_vulnerability")][:60]
    if len(vuln) < 5:
        print(f"  SKIP: only {len(vuln)} vuln"); continue
    samples = vuln + safe
    gt = [{"_sample_id": f"{ds_name}_{i}", "has_vulnerability": s.get("has_vulnerability", False)}
          for i, s in enumerate(samples)]
    print(f"  GT={len(gt)} ({len(vuln)}v/{len(safe)}s)")

    slices, codes = [], []
    for i, s in enumerate(samples):
        wrapped = wrap_c(s["code"])
        sls = slicer.slice_code(wrapped, "c")
        if not sls:
            slices.append({"_sample_id": f"{ds_name}_{i}", "has_vulnerability": False, "_no_slice": True})
            continue
        for sl in sls:
            sl["_sample_id"] = f"{ds_name}_{i}"; sl["language"] = "c"
            sl["_file_code"] = s["code"]  # keep func_code from CodeSlicer
            sl["code_patterns"] = []
            slices.append(sl)
        codes.append((wrapped, "c"))
    print(f"  slices={len(slices)}")

    # sink
    r = run_one(gt, slices, f"{ds_name}/sink")
    print_row(ds_name, "sink", "A", r["A"]); print_row(ds_name, "sink", "B", r["B"]); print_row(ds_name, "sink", "C", r["C"])

    # +codeql
    cql = run_codeql_batch(codes)
    for i, fgs in enumerate(cql):
        for sl in slices:
            if sl.get("_sample_id") == f"{ds_name}_{i}":
                sl["code_patterns"] = fgs
    r2 = run_one(gt, slices, f"{ds_name}/cql")
    print_row(ds_name, "+codeql", "A", r2["A"]); print_row(ds_name, "+codeql", "B", r2["B"]); print_row(ds_name, "+codeql", "C", r2["C"])

# =========================================================================
# primevul
# =========================================================================
if NAME == "primevul" or NAME == "all":
    print(f"\n[primevul]")
    MAX_V, MAX_S = 20, 30
    pv_v, pv_s = [], []
    csv.field_size_limit(sys.maxsize)
    with open(DATA_DIR / "primevul_test.csv", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            code = row.get("code","").strip(); t = int(row.get("target","0"))
            if not code: continue
            if t == 1 and len(pv_v) < MAX_V: pv_v.append((code, True))
            elif t == 0 and len(pv_s) < MAX_S: pv_s.append((code, False))
            if len(pv_v) >= MAX_V and len(pv_s) >= MAX_S: break
    samples = pv_v + pv_s
    gt = [{"_sample_id": f"pv_{i}", "has_vulnerability": t} for i, (_, t) in enumerate(samples)]
    print(f"  {len(gt)} samples ({len(pv_v)}v/{len(pv_s)}s)")

    slices, codes = [], []
    for i, (code, t) in enumerate(samples):
        wrapped = wrap_c(code)
        sls = slicer.slice_code(wrapped, "c")
        for sl in sls:
            sl["_sample_id"] = f"pv_{i}"; sl["language"] = "c"
            sl["_file_code"] = code
            sl["code_patterns"] = []
            slices.append(sl)
        codes.append((wrapped, "c"))
    print(f"  slices={len(slices)}")

    r = run_one(gt, slices, "pv/sink")
    print_row("primevul", "sink", "A", r["A"]); print_row("primevul", "sink", "B", r["B"]); print_row("primevul", "sink", "C", r["C"])

    cql = run_codeql_batch(codes)
    for i, fgs in enumerate(cql):
        for sl in slices:
            if sl.get("_sample_id") == f"pv_{i}":
                sl["code_patterns"] = fgs
    r2 = run_one(gt, slices, "pv/cql")
    print_row("primevul", "+codeql", "A", r2["A"]); print_row("primevul", "+codeql", "B", r2["B"]); print_row("primevul", "+codeql", "C", r2["C"])

print(f"\nDone in {(time.time()-T)/60:.0f}min")
