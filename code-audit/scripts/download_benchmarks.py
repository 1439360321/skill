"""Download benchmark datasets via HuggingFace, sample 100 each, save as JSON."""
import json, sys, random, threading
from pathlib import Path

_PROJ = Path(__file__).resolve().parent.parent
DATA_DIR = _PROJ / "data"
DATA_DIR.mkdir(exist_ok=True)

random.seed(42)
TIMEOUT = 120  # seconds per download attempt


def with_timeout(fn, desc):
    """Run fn with timeout via thread, return None on timeout/failure."""
    result = [None]
    exc = [None]

    def worker():
        try:
            result[0] = fn()
        except Exception as e:
            exc[0] = e

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(TIMEOUT)
    if t.is_alive():
        print(f"  TIMEOUT {desc} ({TIMEOUT}s)")
        return None
    if exc[0]:
        print(f"  SKIP {desc}: {type(exc[0]).__name__}: {exc[0]}")
        return None
    return result[0]


def save_json(name, samples):
    path = DATA_DIR / f"{name}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(samples, f, ensure_ascii=False, indent=2)
    vn = sum(1 for s in samples if s["has_vulnerability"])
    print(f"  Saved: {path} ({len(samples)} samples, {vn} vuln / {len(samples)-vn} safe)")


# =========================================================================
# Devign — via CodeXGLUE (function-level C code)
# =========================================================================
def _download(name, dataset_id, config, code_field, label_field, max_samples=50):
    """Generic downloader with timeout protection."""
    def _do():
        from datasets import load_dataset
        d = load_dataset(dataset_id, config, split="train")
        vuln, safe = [], []
        for item in d:
            target = int(item.get(label_field, 0))
            code = item.get(code_field, "")
            if not code or len(code) < 20:
                continue
            if target == 1 and len(vuln) < max_samples:
                vuln.append({"code": code, "has_vulnerability": True, "file": f"{name}_{len(vuln)}.c"})
            elif target == 0 and len(safe) < max_samples:
                safe.append({"code": code, "has_vulnerability": False, "file": f"{name}_safe_{len(safe)}.c"})
            if len(vuln) >= max_samples and len(safe) >= max_samples:
                break
        return vuln + safe

    samples = with_timeout(_do, name)
    if samples:
        save_json(f"{name}_test_set", samples)


print("[1/3] Juliet (good/bad format)...")
def _download_juliet(max_samples=50):
    def _do():
        from datasets import load_dataset
        d = load_dataset("LorenzH/juliet_test_suite_c_1_3", split="train", streaming=True)
        vuln, safe = [], []
        for item in d:
            if len(vuln) >= max_samples and len(safe) >= max_samples:
                break
            bad = item.get("bad", ""); good = item.get("good", "")
            if bad and len(bad) > 20 and len(vuln) < max_samples:
                vuln.append({"code": bad, "has_vulnerability": True, "file": f"juliet_{len(vuln)}.c"})
            if good and len(good) > 20 and len(safe) < max_samples:
                safe.append({"code": good, "has_vulnerability": False, "file": f"juliet_safe_{len(safe)}.c"})
        return vuln + safe
    samples = with_timeout(_do, "juliet")
    if samples: save_json("juliet_test_set", samples)
_download_juliet()

print("[2/3] D2A (code split, bug_function+label fields)...")
def _download_d2a(max_samples=50):
    def _do():
        from datasets import load_dataset
        # Try dev split first (has more vuln), fall back to train
        vuln, safe = [], []
        for split in ["dev", "test", "train"]:
            try:
                d = load_dataset("claudios/D2A", "code", split=split)
                for item in d:
                    if len(vuln) >= max_samples and len(safe) >= max_samples:
                        break
                    label = int(item.get("label", 0))
                    code = item.get("bug_function", item.get("code", ""))
                    if not code or len(code) < 20: continue
                    if label == 1 and len(vuln) < max_samples:
                        vuln.append({"code": code, "has_vulnerability": True, "file": f"d2a_{len(vuln)}.c"})
                    elif label == 0 and len(safe) < max_samples:
                        safe.append({"code": code, "has_vulnerability": False, "file": f"d2a_safe_{len(safe)}.c"})
                if len(vuln) >= 5: break  # found some vulns
            except Exception:
                continue
        return vuln + safe
    samples = with_timeout(_do, "d2a")
    if samples and sum(1 for s in samples if s["has_vulnerability"]) >= 5:
        save_json("d2a_test_set", samples)
    else:
        print(f"  SKIP D2A: only {sum(1 for s in samples if s['has_vulnerability']) if samples else 0} vuln samples")
_download_d2a()

print("[3/3] Devign — SKIP (legacy format unsupported by new HF datasets)")

print("\nDone — check data/ for *_test_set.json files")
