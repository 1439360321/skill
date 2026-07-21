"""V4 confirm_it vs flag_it on 200 stratified PrimeVul samples."""
import csv, os, sys, time

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


def load_client():
    from shared.llm.openai_client import OpenAIClient
    return OpenAIClient(api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
                        base_url="https://api.deepseek.com", model="deepseek-chat")


def load_stratified(n=200):
    csv.field_size_limit(sys.maxsize)
    vuln, safe = [], []
    with open("data/primevul_test.csv", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            t = int(row.get("target", "0"))
            s = {"code": row["code"], "label": "vuln" if t == 1 else "safe"}
            if t == 1 and len(vuln) < n // 2: vuln.append(s)
            elif t == 0 and len(safe) < n // 2: safe.append(s)
            if len(vuln) >= n // 2 and len(safe) >= n // 2: break
    return vuln + safe


def metrics(results):
    valid = [r for r in results if r.get("verdict") != "skip"]
    tp = sum(1 for r in valid if r["label"] == "vuln" and r["verdict"] == "vuln")
    fp = sum(1 for r in valid if r["label"] == "safe" and r["verdict"] == "vuln")
    fn = sum(1 for r in valid if r["label"] == "vuln" and r["verdict"] == "safe")
    tn = sum(1 for r in valid if r["label"] == "safe" and r["verdict"] == "safe")
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    return {"F1": f1, "P": p, "R": r, "FPR": fpr, "TP": tp, "FP": fp, "FN": fn, "TN": tn}


def run_config(client, samples, params, name):
    print(f"\n{'='*60}")
    print(f"{name}")
    print(f"{'='*60}")
    slicer = CodeSlicer()
    results = []
    t0 = time.time()
    total_calls = 0

    for i, s in enumerate(samples):
        sd_list = slicer.slice_code(s["code"], "c")
        if not sd_list or not sd_list[0].get("code"):
            results.append({"label": s["label"], "verdict": "skip"})
            continue
        r = run_pipeline(sd_list[0], client, params)
        results.append({
            "label": s["label"],
            "verdict": r.get("final_verdict", "?"),
        })
        total_calls += r.get("_llm_calls", 0)
        if (i + 1) % 50 == 0:
            m = metrics(results)
            print(f"  [{i+1:3d}/{len(samples)}] F1={m['F1']:.4f} P={m['P']:.4f} R={m['R']:.4f} "
                  f"TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']} calls={total_calls}")

    elapsed = time.time() - t0
    m = metrics(results)
    print(f"  FINAL F1={m['F1']:.4f} P={m['P']:.4f} R={m['R']:.4f} FPR={m['FPR']:.4f} "
          f"TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']} {elapsed:.0f}s {total_calls}calls")
    return m


def main():
    client = load_client()
    print("DeepSeek V4 Flash...", end=" ")
    client.generate("OK", temperature=0, max_tokens=5)
    print("OK\n")

    samples = load_stratified(200)
    print(f"Loaded {len(samples)} stratified samples")

    # V4 confirm_it
    r1 = run_config(client, samples, get_params("v4"), "V4 confirm_it")

    # V4 flag_it
    p = get_params("v4")
    p["llm"]["agent2_bias"] = "flag_it"
    r2 = run_config(client, samples, p, "V4 flag_it")

    print(f"\n{'='*60}")
    print(f"COMPARISON (200 PrimeVul stratified)")
    print(f"{'='*60}")
    print(f"  {'Config':<20} {'F1':>6} {'P':>6} {'R':>6} {'FPR':>6}")
    for name, r in [("V4 confirm_it", r1), ("V4 flag_it", r2)]:
        print(f"  {name:<20} {r['F1']:.4f} {r['P']:.4f} {r['R']:.4f} {r['FPR']:.4f}")


if __name__ == "__main__":
    main()
