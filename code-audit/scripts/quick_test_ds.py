"""Quick test: 2 PrimeVul samples with DeepSeek V4 Flash + V3 preset."""
import csv
import os
import sys
import time

sys.path.insert(0, ".")

# Load .env manually (avoid python-dotenv dependency)
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
        model="deepseek-chat",  # V4 Flash
    )


def load_primevul_samples(path: str, n: int = 2):
    with open(path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        samples = []
        for row in reader:
            code = row.get("code", "")
            target = int(row.get("target", "0"))
            samples.append({
                "code": code,
                "label": "vuln" if target == 1 else "safe",
                "project": row.get("project", ""),
                "cwe": row.get("cwe", ""),
            })
            if len(samples) >= n:
                break
    return samples


def test_one(client, sample: dict, preset: dict, index: int):
    code = sample["code"]
    print(f"\n{'='*60}")
    print(f"Sample {index}: label={sample['label']}, cwe={sample['cwe']}, {len(code)} chars")
    print(f"{'='*60}")

    # Run CodeSlicer
    start = time.time()
    slicer = CodeSlicer()
    sd_list = slicer.slice_code(code, "c")
    if not sd_list or not sd_list[0].get("code"):
        print("  SKIP: CodeSlicer returned empty slice")
        return
    sd = sd_list[0]
    print(f"  Sink: {sd.get('sink_type', 'none')}, Risk: {sd.get('risk_level', 'none')}")

    # Run pipeline — V4 (Tool-Aware Chain) with PrimeVul-friendly settings
    params = get_params("v4")

    result = run_pipeline(sd, client, params)
    elapsed = time.time() - start

    print(f"\n  Verdict: {result.get('final_verdict')}")
    print(f"  Method:  {result.get('final_method')}")
    print(f"  Conf:    {result.get('final_confidence')}")
    print(f"  Calls:   {result.get('_llm_calls', '?')}")
    print(f"  Time:    {elapsed:.1f}s")
    print(f"  Cache:   {result.get('_cache_hit', False)}")
    print(f"  Reason:  {result.get('llm_reasoning', '')[:200]}")

    # Agent details
    a1 = result.get("_agent1_raw", {}) or result.get("_agent1_parsed", {})
    a2 = result.get("_agent2_raw", {})
    a3 = result.get("_agent3_raw", {})
    ws = result.get("_window_suggestion", "?")
    rag = result.get("_rag_context", "")
    print(f"\n  A1: verdict={a1.get('initial_verdict', a1.get('verdict', '?'))}, conf={a1.get('confidence', '?')}, window={ws}")
    print(f"  A2: {a2.get('verdict', '?')}, conf={a2.get('confidence', '?')}")
    if a3:
        print(f"  A3: has_vuln={a3.get('has_vulnerability')}, conf={a3.get('confidence', '?')}")
    else:
        print(f"  A3: no blind-spot findings (ran, returned None)")
    if rag:
        print(f"  RAG: {rag[:150]}...")

    return result


def main():
    client = load_client()
    print("Testing DeepSeek V4 Flash connectivity...")
    try:
        resp = client.generate("Reply with just 'OK'", temperature=0, max_tokens=10)
        print(f"  Response: {resp[:50]}")
    except Exception as e:
        print(f"  FAIL: {e}")
        return

    path = "data/primevul_test.csv"
    samples = load_primevul_samples(path, n=2)

    preset = get_params("v4")

    for i, s in enumerate(samples):
        test_one(client, s, preset, i + 1)

    print(f"\n{'='*60}")
    print("Done. Check the output above for issues.")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
