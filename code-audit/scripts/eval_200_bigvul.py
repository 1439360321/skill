"""200-sample BigVul clean evaluation — V4 pipeline with confirm_it."""
import json
import os
import sys
import time
from datetime import datetime

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


def main():
    client = load_client()
    print("DeepSeek V4 Flash check...", end=" ")
    try:
        client.generate("OK", temperature=0, max_tokens=5)
        print("OK")
    except Exception as e:
        print(f"FAIL: {e}")
        return

    with open("data/bigvul_clean_200.json", encoding="utf-8") as f:
        samples = json.load(f)
    print(f"Loaded: {len(samples)} BigVul samples (clean, untruncated)")
    print(f"V4 preset | confirm_it | DeepSeek V4 Flash | {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print()

    params = get_params("v4")
    slicer = CodeSlicer()
    results = []
    t0 = time.time()
    total_calls = 0
    skips = 0

    for i, s in enumerate(samples):
        sd_list = slicer.slice_code(s["code"], "c")
        if not sd_list or not sd_list[0].get("code"):
            results.append({
                "label": s["label"], "sink": "none", "verdict": "skip",
                "method": "codeslicer_empty", "confidence": 0, "calls": 0,
                "time": 0, "window": "", "a2_verdict": "", "a3_ran": False,
            })
            skips += 1
            continue

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
        a2 = result.get("_agent2_raw", {})
        a3 = result.get("_agent3_raw")

        results.append({
            "index": i + 1,
            "label": s["label"],
            "cwe": s.get("cwe", ""),
            "sink": sink,
            "risk": risk,
            "verdict": verdict,
            "method": method,
            "confidence": conf,
            "calls": calls,
            "time": round(elapsed, 1),
            "window": window,
            "a2_verdict": a2.get("verdict", ""),
            "a2_conf": a2.get("confidence", 0),
            "a3_ran": a3 is not None,
        })
        total_calls += calls

        if (i + 1) % 20 == 0:
            elapsed_total = time.time() - t0
            eta = elapsed_total / (i + 1) * (len(samples) - i - 1)
            print(f"  [{i+1:3d}/{len(samples)}] {elapsed_total:.0f}s, ETA {eta:.0f}s")

    elapsed = time.time() - t0
    valid = [r for r in results if r.get("verdict") != "skip"]

    tp = fp = fn = tn = 0
    for r in valid:
        gt = r["label"] == "vuln"
        pred = r["verdict"] == "vuln"
        if gt and pred: tp += 1
        elif not gt and pred: fp += 1
        elif gt and not pred: fn += 1
        else: tn += 1
    total = tp + fp + fn + tn
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * rec / (p + rec) if (p + rec) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    acc = (tp + tn) / total if total > 0 else 0

    print(f"\n{'='*60}")
    print(f"BigVul clean: {len(valid)} valid + {skips} skipped, {elapsed:.0f}s, {total_calls} calls")
    print(f"P={p:.4f}  R={rec:.4f}  F1={f1:.4f}  FPR={fpr:.4f}  Acc={acc:.4f}")
    print(f"TP={tp}  FP={fp}  FN={fn}  TN={tn}")

    with_sink = [r for r in valid if r.get("sink") != "none"]
    no_sink = [r for r in valid if r.get("sink") == "none"]
    for name, subset in [("With sink", with_sink), ("No sink", no_sink)]:
        if not subset:
            continue
        s_tp = sum(1 for r in subset if r["label"] == "vuln" and r["verdict"] == "vuln")
        s_fp = sum(1 for r in subset if r["label"] == "safe" and r["verdict"] == "vuln")
        s_fn = sum(1 for r in subset if r["label"] == "vuln" and r["verdict"] == "safe")
        s_tn = sum(1 for r in subset if r["label"] == "safe" and r["verdict"] == "safe")
        s_p = s_tp / (s_tp + s_fp) if (s_tp + s_fp) > 0 else 0
        s_r = s_tp / (s_tp + s_fn) if (s_tp + s_fn) > 0 else 0
        s_f1 = 2 * s_p * s_r / (s_p + s_r) if (s_p + s_r) > 0 else 0
        print(f"  {name} ({len(subset)}): P={s_p:.4f} R={s_r:.4f} F1={s_f1:.4f}")

    methods = {}
    for r in valid:
        m = r.get("method", "?")
        methods[m] = methods.get(m, 0) + 1
    print(f"\nMethod distribution:")
    for m, c in sorted(methods.items(), key=lambda x: -x[1]):
        print(f"  {m}: {c}")

    os.makedirs("reports", exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    csv_path = f"reports/eval_200_bigvul_{ts}.csv"
    import csv as csv_mod
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv_mod.DictWriter(f, fieldnames=[
            "index", "label", "cwe", "sink", "risk", "verdict", "method",
            "confidence", "calls", "time", "window", "a2_verdict", "a2_conf", "a3_ran"
        ])
        writer.writeheader()
        writer.writerows(results)
    print(f"\nSaved to {csv_path}")


if __name__ == "__main__":
    main()
