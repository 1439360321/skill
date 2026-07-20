"""Quick test: 30 PrimeVul samples WITH sink functions — V4 pipeline."""
import csv
import os
import re
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

SINK_RE = re.compile(
    r'\b(strcpy|strcat|sprintf|memcpy|gets|scanf|system|popen|execve|execl|execvp'
    r'|printf|fprintf|free|malloc|calloc|realloc|send|recv|read|write|fopen)\s*\('
)


def load_client():
    from shared.llm.openai_client import OpenAIClient
    return OpenAIClient(
        api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
    )


def main():
    client = load_client()
    print("Testing DeepSeek V4 Flash...", end=" ")
    try:
        client.generate("OK", temperature=0, max_tokens=5)
        print("OK")
    except Exception as e:
        print(f"FAIL: {e}")
        return

    # Load PrimeVul sink-heavy samples
    csv.field_size_limit(sys.maxsize)
    vuln_samples = []
    safe_samples = []
    with open("data/primevul_test.csv", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            code = row.get("code", "")
            if not SINK_RE.search(code):
                continue
            target = int(row.get("target", "0"))
            s = {
                "code": code,
                "label": "vuln" if target == 1 else "safe",
                "cwe": row.get("cwe", ""),
            }
            if target == 1:
                vuln_samples.append(s)
            else:
                safe_samples.append(s)
            if len(vuln_samples) >= 15 and len(safe_samples) >= 15:
                break

    samples = vuln_samples[:15] + safe_samples[:15]
    print(f"Loaded: {len(vuln_samples[:15])} vuln + {len(safe_samples[:15])} safe = {len(samples)} sink-heavy PrimeVul samples")

    params = get_params("v4")
    results = []
    t0 = time.time()
    total_calls = 0

    for i, s in enumerate(samples):
        code = s["code"]
        label = s["label"]
        cwe = s.get("cwe", "")

        slicer = CodeSlicer()
        sd_list = slicer.slice_code(code, "c")
        if not sd_list or not sd_list[0].get("code"):
            results.append({"_skip": True, "label": label})
            print(f"  [{i+1:2d}] label={label:4s} SKIP: CodeSlicer empty")
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
            "_skip": False, "label": label, "cwe": cwe, "sink": sink, "risk": risk,
            "verdict": verdict, "method": method, "confidence": conf,
            "calls": calls, "time": round(elapsed, 1), "window": window,
            "a2_verdict": a2.get("verdict", "?"), "a2_conf": a2.get("confidence", 0),
            "a3_ran": a3 is not None,
        })
        total_calls += calls

        print(f"  [{i+1:2d}] label={label:4s} sink={sink:12s} risk={risk:6s} "
              f"→ {verdict:4s} ({method:30s}) "
              f"conf={conf:.2f} calls={calls} win={window:6s} "
              f"a2={a2.get('verdict','?'):14s} a2_c={a2.get('confidence',0):.2f}")

    elapsed = time.time() - t0
    valid = [r for r in results if not r.get("_skip")]

    # Metrics
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
    acc = (tp + tn) / total if total > 0 else 0

    print(f"\n{'='*60}")
    print(f"Sink-heavy PrimeVul: {len(valid)} samples in {elapsed:.0f}s, "
          f"{total_calls} LLM calls")
    print(f"P={p:.4f} R={rec:.4f} F1={f1:.4f} Acc={acc:.4f} "
          f"TP={tp} FP={fp} FN={fn} TN={tn}")

    # Breakdown
    with_sink = [r for r in valid if r.get("sink") != "none"]
    no_sink = [r for r in valid if r.get("sink") == "none"]
    print(f"\nWith CodeSlicer sink: {len(with_sink)} samples")
    print(f"No CodeSlicer sink:  {len(no_sink)} samples (sink from regex only)")

    # Method distribution
    methods = {}
    for r in valid:
        m = r.get("method", "?")
        methods[m] = methods.get(m, 0) + 1
    print(f"\nMethod distribution:")
    for m, c in sorted(methods.items(), key=lambda x: -x[1]):
        print(f"  {m}: {c}")

    # vs earlier no-sink results
    print(f"\nComparison:")
    print(f"  No-sink  (29 samples): F1=0.45 P=0.71 R=0.33")
    print(f"  Sink-rich(30 samples): F1={f1:.4f} P={p:.4f} R={rec:.4f}")


if __name__ == "__main__":
    main()
