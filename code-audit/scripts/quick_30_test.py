"""Quick 30-sample test: 15 BigVul (sink-heavy) + 15 PrimeVul (logic-heavy) with V4 pipeline."""
import csv
import json
import os
import sys
import time

sys.path.insert(0, ".")

_env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
if os.path.exists(_env_path):
    with open(_env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

from src.llm.pipeline.orchestrator import run_pipeline, get_params
from src.scanner.code_slicer import CodeSlicer


def load_client():
    from shared.llm.openai_client import OpenAIClient
    return OpenAIClient(
        api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
    )


def load_bigvul_samples(path: str, n: int = 15):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    # Pick balanced mix of vuln + safe
    vuln = [s for s in data if s.get("has_vulnerability")]
    safe = [s for s in data if not s.get("has_vulnerability")]
    half = n // 2
    samples = (vuln[:half] + safe[:half])[:n]
    out = []
    for s in samples:
        out.append({
            "code": s.get("code", ""),
            "label": "vuln" if s.get("has_vulnerability") else "safe",
            "cwe": s.get("cwe_id", ""),
            "dataset": "BigVul",
        })
    return out


def load_primevul_samples(path: str, n: int = 15):
    import csv
    csv.field_size_limit(sys.maxsize)
    with open(path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        vuln_rows = []
        safe_rows = []
        for row in reader:
            target = int(row.get("target", "0"))
            if target == 1:
                vuln_rows.append(row)
            else:
                safe_rows.append(row)
    half = n // 2
    selected = vuln_rows[:half] + safe_rows[:half]
    out = []
    for row in selected:
        out.append({
            "code": row.get("code", ""),
            "label": "vuln" if int(row.get("target", "0")) == 1 else "safe",
            "cwe": row.get("cwe", ""),
            "project": row.get("project", ""),
            "dataset": "PrimeVul",
        })
    return out


def run_sample(client, sample: dict, params: dict, index: int):
    code = sample["code"]
    dataset = sample["dataset"]
    label = sample["label"]
    cwe = sample.get("cwe", "")

    slicer = CodeSlicer()
    sd_list = slicer.slice_code(code, "c")
    if not sd_list or not sd_list[0].get("code"):
        return {"_skip": True, "_reason": "CodeSlicer empty"}

    sd = sd_list[0]
    sink = sd.get("sink_type") or "none"
    risk = sd.get("risk_level", "?")

    start = time.time()
    result = run_pipeline(sd, client, params)
    elapsed = time.time() - start

    verdict = result.get("final_verdict", "?")
    method = result.get("final_method", "?")
    conf = result.get("final_confidence", 0)
    calls = result.get("_llm_calls", 0)
    window = result.get("_window_suggestion", "?")
    a1 = result.get("_agent1_parsed", {})
    a2 = result.get("_agent2_raw", {})
    a3 = result.get("_agent3_raw")

    return {
        "_skip": False,
        "index": index,
        "dataset": dataset,
        "label": label,
        "cwe": cwe,
        "sink": sink,
        "risk": risk,
        "verdict": verdict,
        "method": method,
        "confidence": conf,
        "calls": calls,
        "time": round(elapsed, 1),
        "window": window,
        "a1_verdict": a1.get("initial_verdict", a1.get("verdict", "?")),
        "a1_conf": a1.get("confidence", 0),
        "a2_verdict": a2.get("verdict", "?"),
        "a2_conf": a2.get("confidence", 0),
        "a3_ran": a3 is not None,
        "a1_reason": (a1.get("reasoning", "") or "")[:80],
        "a2_reason": (a2.get("reasoning", "") or "")[:80],
    }


def compute_metrics(results):
    tp = fp = fn = tn = 0
    for r in results:
        if r.get("_skip"):
            continue
        gt = r["label"] == "vuln"
        pred = r["verdict"] == "vuln"
        if gt and pred: tp += 1
        elif not gt and pred: fp += 1
        elif gt and not pred: fn += 1
        else: tn += 1
    total = tp + fp + fn + tn
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
    acc = (tp + tn) / total if total > 0 else 0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "Total": total,
            "Precision": round(p, 4), "Recall": round(r, 4),
            "F1": round(f1, 4), "Accuracy": round(acc, 4)}


def main():
    client = load_client()
    print("Testing DeepSeek V4 Flash...", end=" ")
    try:
        resp = client.generate("OK", temperature=0, max_tokens=5)
        print("OK")
    except Exception as e:
        print(f"FAIL: {e}")
        return

    # Load samples
    bv_samples = load_bigvul_samples("data/bigvul_test_set.json", n=16)
    pv_samples = load_primevul_samples("data/primevul_test.csv", n=14)
    samples = bv_samples + pv_samples
    print(f"Loaded: {len(bv_samples)} BigVul + {len(pv_samples)} PrimeVul = {len(samples)} total")

    params = get_params("v4")
    results = []
    t0 = time.time()
    total_calls = 0

    for i, s in enumerate(samples):
        sd = s["dataset"]
        label = s["label"]
        code_len = len(s["code"])
        cwe = s.get("cwe", "")

        r = run_sample(client, s, params, i + 1)
        results.append(r)
        total_calls += r.get("calls", 0)

        if r.get("_skip"):
            print(f"  [{i+1:2d}] {sd:8s} label={label:4s} SKIP: {r['_reason']}")
        else:
            print(f"  [{i+1:2d}] {sd:8s} label={label:4s} sink={r['sink']:10s} "
                  f"→ {r['verdict']:4s} ({r['method']:30s}) "
                  f"conf={r['confidence']:.2f} calls={r['calls']} "
                  f"win={r['window']:6s} | {r['a2_verdict']:14s} a2={r['a2_conf']:.2f} "
                  f"a3={'yes' if r['a3_ran'] else 'no'}")

    elapsed = time.time() - t0
    print(f"\n{'='*70}")
    print(f"Done. {len([r for r in results if not r.get('_skip')])} samples in {elapsed:.0f}s, "
          f"{total_calls} total LLM calls, avg {elapsed/len(results):.1f}s/sample")

    # Per-dataset metrics
    for ds in ["BigVul", "PrimeVul"]:
        ds_results = [r for r in results if r.get("dataset") == ds]
        m = compute_metrics(ds_results)
        print(f"\n{ds}: P={m['Precision']} R={m['Recall']} F1={m['F1']} "
              f"Acc={m['Accuracy']} TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']}")

    # Overall
    m = compute_metrics(results)
    print(f"\nOverall: P={m['Precision']} R={m['Recall']} F1={m['F1']} "
          f"Acc={m['Accuracy']} TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']}")

    # Breakdown by method
    methods = {}
    for r in results:
        if r.get("_skip"):
            continue
        m = r.get("method", "?")
        methods[m] = methods.get(m, 0) + 1
    print(f"\nMethod distribution:")
    for m, c in sorted(methods.items(), key=lambda x: -x[1]):
        print(f"  {m}: {c}")

    # Breakdown by sink presence
    with_sink = [r for r in results if not r.get("_skip") and r.get("sink") != "none"]
    no_sink = [r for r in results if not r.get("_skip") and r.get("sink") == "none"]
    if with_sink:
        ms = compute_metrics(with_sink)
        print(f"\nWith sink ({len(with_sink)}): F1={ms['F1']} P={ms['Precision']} R={ms['Recall']}")
    if no_sink:
        mn = compute_metrics(no_sink)
        print(f"\nNo sink   ({len(no_sink)}): F1={mn['F1']} P={mn['Precision']} R={mn['Recall']}")


if __name__ == "__main__":
    main()
