"""30-sample ablation: no-RAG + single-pass baselines on sink-heavy PrimeVul."""
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
    r'\b(strcpy|strcat|sprintf|memcpy|memmove|gets|scanf|system|popen|execve'
    r'|printf|fprintf|free|malloc|calloc|realloc|send|recv|read|write|fopen)\s*\('
)


def load_client():
    from shared.llm.openai_client import OpenAIClient
    return OpenAIClient(
        api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
    )


def load_samples(n=30):
    csv.field_size_limit(sys.maxsize)
    vuln = []; safe = []
    with open("data/primevul_test.csv", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not SINK_RE.search(row.get("code", "")):
                continue
            t = int(row.get("target", "0"))
            s = {"code": row["code"], "label": "vuln" if t == 1 else "safe"}
            if t == 1 and len(vuln) < n//2: vuln.append(s)
            elif t == 0 and len(safe) < n//2: safe.append(s)
            if len(vuln) >= n//2 and len(safe) >= n//2: break
    return vuln + safe


def run_config(client, samples, params, name):
    print(f"\n{'='*60}")
    print(f"Config: {name}")
    print(f"{'='*60}")
    slicer = CodeSlicer()
    results = []
    t0 = time.time()
    calls = 0

    for i, s in enumerate(samples):
        sd_list = slicer.slice_code(s["code"], "c")
        if not sd_list or not sd_list[0].get("code"):
            results.append({"label": s["label"], "verdict": "skip"})
            continue
        sd = sd_list[0]
        start = time.time()
        result = run_pipeline(sd, client, params)
        elapsed = time.time() - start
        results.append({
            "label": s["label"],
            "verdict": result.get("final_verdict", "?"),
            "method": result.get("final_method", "?"),
            "confidence": result.get("final_confidence", 0),
            "calls": result.get("_llm_calls", 0),
            "time": elapsed,
            "sink": sd.get("sink_type") or "none",
        })
        calls += result.get("_llm_calls", 0)

    elapsed = time.time() - t0
    valid = [r for r in results if r.get("verdict") != "skip"]
    tp = sum(1 for r in valid if r["label"] == "vuln" and r["verdict"] == "vuln")
    fp = sum(1 for r in valid if r["label"] == "safe" and r["verdict"] == "vuln")
    fn = sum(1 for r in valid if r["label"] == "vuln" and r["verdict"] == "safe")
    tn = sum(1 for r in valid if r["label"] == "safe" and r["verdict"] == "safe")
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * rec / (p + rec) if (p + rec) > 0 else 0
    acc = (tp + tn) / (tp + fp + fn + tn)

    print(f"  P={p:.4f} R={rec:.4f} F1={f1:.4f} Acc={acc:.4f}")
    print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"  {elapsed:.0f}s, {calls} calls")
    return {"F1": f1, "P": p, "R": rec, "TP": tp, "FP": fp, "FN": fn, "TN": tn}


def run_single_pass_fair(client, samples):
    """Fair baseline: 1 LLM call, confirm_it prompt, full code, no static filter."""
    from src.llm.pipeline.llm_strategy import VERIFIER_PROMPT_V4, parse_json
    slicer = CodeSlicer()
    results = []
    t0 = time.time()

    for s in samples:
        sd_list = slicer.slice_code(s["code"], "c")
        if not sd_list or not sd_list[0].get("code"):
            results.append({"label": s["label"], "verdict": "skip"})
            continue
        sd = sd_list[0]
        sink = sd.get("sink_type") or "none"
        category = sd.get("sink_category", "generic")
        sank = sd.get("sanitization_detail", "none")
        df = sd.get("dataflow_path", "?")
        sources = sd.get("source_var", "unknown")
        code = sd.get("code", s["code"])

        prompt = VERIFIER_PROMPT_V4.format(
            category=category,
            reasoning=f"Verify sink={sink} for {category}",
            sink=sink, sources=sources, sanitizers=sank, dataflow=df,
            language="c", code_keyline=code,
        )

        try:
            resp = client.generate(prompt, temperature=0.1, max_tokens=1024)
            parsed = parse_json(resp, "robust")
        except Exception:
            parsed = None

        if parsed:
            verdict = "vuln" if parsed.get("verdict") == "vulnerable" else "safe"
            conf = parsed.get("confidence", 0.5)
        else:
            verdict = "safe"
            conf = 0.5

        results.append({
            "label": s["label"], "verdict": verdict, "method": "fair_single_pass",
            "confidence": conf, "calls": 1, "time": time.time() - t0, "sink": sink,
        })

    valid = [r for r in results if r.get("verdict") != "skip"]
    tp = sum(1 for r in valid if r["label"] == "vuln" and r["verdict"] == "vuln")
    fp = sum(1 for r in valid if r["label"] == "safe" and r["verdict"] == "vuln")
    fn = sum(1 for r in valid if r["label"] == "vuln" and r["verdict"] == "safe")
    tn = sum(1 for r in valid if r["label"] == "safe" and r["verdict"] == "safe")
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * rec / (p + rec) if (p + rec) > 0 else 0
    acc = (tp + tn) / (tp + fp + fn + tn)
    return {"F1": f1, "P": p, "R": rec, "TP": tp, "FP": fp, "FN": fn, "TN": tn}


def main():
    client = load_client()
    print("DeepSeek V4 Flash...", end=" ")
    try:
        client.generate("OK", temperature=0, max_tokens=5)
        print("OK")
    except Exception as e:
        print(f"FAIL: {e}"); return

    samples = load_samples(30)
    print(f"Loaded {len(samples)} sink-heavy PrimeVul samples")

    # 1. Fair single-pass: 1 call, confirm_it prompt, full code, no static filter
    r0 = run_single_pass_fair(client, samples)
    print(f"\n{'='*60}")
    print("Config: Fair Single-Pass (1 call, confirm_it, full code, no filter)")
    print(f"{'='*60}")
    print(f"  P={r0['P']:.4f} R={r0['R']:.4f} F1={r0['F1']:.4f}")
    print(f"  TP={r0['TP']} FP={r0['FP']} FN={r0['FN']} TN={r0['TN']}")

    # 2. No-RAG: V4 preset but without RAG
    params_no_rag = get_params("v4")
    params_no_rag["llm"]["enable_rag"] = False
    r1 = run_config(client, samples, params_no_rag, "No RAG (V4 - RAG)")

    # 3. Single-pass: V3 preset (for reference — has static filter)
    params_v3 = get_params("v3")
    r2 = run_config(client, samples, params_v3, "Single-pass (V3, with filter)")

    # 4. V4 full
    params_v4 = get_params("v4")
    r3 = run_config(client, samples, params_v4, "V4 full (confirm_it + RAG)")

    print(f"\n{'='*60}")
    print("ABLATION SUMMARY")
    print(f"{'='*60}")
    print(f"  {'Config':<30} {'F1':>6} {'P':>6} {'R':>6} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}")
    for name, r in [("Fair Single-Pass", r0), ("No RAG", r1), ("V3 (filtered)", r2), ("V4 full", r3)]:
        print(f"  {name:<30} {r['F1']:.4f} {r['P']:.4f} {r['R']:.4f} {r['TP']:>4} {r['FP']:>4} {r['FN']:>4} {r['TN']:>4}")


if __name__ == "__main__":
    main()
