"""V4 ablation: 6 configs, 30 stratified samples. single_pass baseline."""
import csv, os, re, sys, time

sys.path.insert(0, ".")
_env = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
if os.path.exists(_env):
    with open(_env) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

from src.llm.pipeline.orchestrator import run_pipeline, get_params
from src.scanner.code_slicer import CodeSlicer

SINK_RE = re.compile(
    r'\b(strcpy|strcat|sprintf|memcpy|memmove|gets|scanf|system|popen|execve'
    r'|printf|fprintf|free|malloc|calloc|realloc|send|recv|read|write|fopen)\s*\(')


def load_client():
    from shared.llm.openai_client import OpenAIClient
    return OpenAIClient(api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
                        base_url="https://api.deepseek.com", model="deepseek-chat")


def load_samples(n=30):
    csv.field_size_limit(sys.maxsize)
    v_s, s_s, v_n, s_n = [], [], [], []
    per = n // 4
    with open("data/primevul_test.csv", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            t = int(row.get("target", "0"))
            code = row.get("code", "")
            has = bool(SINK_RE.search(code))
            if t == 1 and has and len(v_s) < per: v_s.append({"code": code, "label": "vuln"})
            elif t == 0 and has and len(s_s) < per: s_s.append({"code": code, "label": "safe"})
            elif t == 1 and not has and len(v_n) < per: v_n.append({"code": code, "label": "vuln"})
            elif t == 0 and not has and len(s_n) < per: s_n.append({"code": code, "label": "safe"})
            if all(len(b) >= per for b in [v_s, s_s, v_n, s_n]):
                break
    return v_s + s_s + v_n + s_n


def metrics(results):
    valid = [r for r in results if r.get("verdict") != "skip"]
    tp = sum(1 for r in valid if r["label"] == "vuln" and r["verdict"] == "vuln")
    fp = sum(1 for r in valid if r["label"] == "safe" and r["verdict"] == "vuln")
    fn = sum(1 for r in valid if r["label"] == "vuln" and r["verdict"] == "safe")
    tn = sum(1 for r in valid if r["label"] == "safe" and r["verdict"] == "safe")
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
    calls = sum(r.get("calls", 0) for r in results)
    return {"F1": f1, "P": p, "R": r, "TP": tp, "FP": fp, "FN": fn, "TN": tn, "calls": calls}


def run_one(client, samples, params, name):
    print(f"  [{name}] ", end="", flush=True)
    slicer = CodeSlicer()
    results = []
    t0 = time.time()
    for s in samples:
        sd_list = slicer.slice_code(s["code"], "c")
        if not sd_list or not sd_list[0].get("code"):
            results.append({"label": s["label"], "verdict": "skip", "calls": 0})
            continue
        r = run_pipeline(sd_list[0], client, params)
        results.append({
            "label": s["label"],
            "verdict": r.get("final_verdict", "?"),
            "calls": r.get("_llm_calls", 0),
        })
    elapsed = time.time() - t0
    m = metrics(results)
    print(f"F1={m['F1']:.4f} P={m['P']:.4f} R={m['R']:.4f} "
          f"TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']} "
          f"calls={m['calls']} {elapsed:.0f}s")
    return m


def main():
    client = load_client()
    print("DeepSeek V4 Flash...", end=" ")
    client.generate("OK", temperature=0, max_tokens=5)
    print("OK\n")

    samples = load_samples(30)
    print(f"Loaded: {sum(1 for s in samples if SINK_RE.search(s['code']))} with sink, "
          f"{sum(1 for s in samples if not SINK_RE.search(s['code']))} without sink")

    configs = []

    # 0. Baseline: single_pass, fair
    p = get_params("v3")
    p["static_decision"] = {"no_sink": "uncertain", "low_risk_sink": "uncertain",
                             "sanitizer_threshold": 0, "dataflow_required": False}
    p["code_window"] = {"mode": "simple", "simple_max_chars": 100000}
    configs.append(("BASELINE single_pass fair", p))

    # 1. V4 tool_aware_chain
    configs.append(("V4 tool_aware_chain", get_params("v4")))

    # 2. V4 flag_it
    p = get_params("v4")
    p["llm"]["agent2_bias"] = "flag_it"
    configs.append(("V4 Agent2 flag_it", p))

    # 3. V4 no RAG
    p = get_params("v4")
    p["llm"]["enable_rag"] = False
    configs.append(("V4 no RAG", p))

    # 4. single_pass + static filter (original V3 preset)
    configs.append(("Mode1 + static filter (V3 orig)", get_params("v3")))

    # 5. V4 multi-temp weighted voting
    p = get_params("v4")
    p["llm"]["agent2_temperatures"] = [0.0, 0.3, 0.7]
    p["llm"]["voting_threshold"] = 0.5
    configs.append(("V4 Agent2 multi-temp", p))

    # Run
    print("=" * 70)
    results = {}
    for name, params in configs:
        results[name] = run_one(client, samples, params, name)

    # Summary
    baseline = results["BASELINE single_pass fair"]
    print(f"\n{'='*70}")
    print(f"Baseline (single_pass): F1={baseline['F1']:.4f} P={baseline['P']:.4f} R={baseline['R']:.4f} calls={baseline['calls']}")
    print(f"\n{'Config':<35} {'F1':>6} {'P':>6} {'R':>6} {'ΔF1':>7} {'calls':>5}")
    print(f"{'-'*60}")
    for name, m in results.items():
        if "BASELINE" in name: continue
        d = m["F1"] - baseline["F1"]
        print(f"  {name:<35} {m['F1']:.4f} {m['P']:.4f} {m['R']:.4f} {d:+.4f} {m['calls']:>5}")


if __name__ == "__main__":
    main()
