"""Semgrep runner — batch analysis for Python code snippets.

Designed as a signal provider for LLM pipeline, NOT a standalone detector.
Findings are injected as code_patterns in slice data.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import hashlib
from pathlib import Path
from typing import Any

from src.utils.logger import setup_logger

logger = setup_logger()

# Semgrep rule packs for Python security
PYTHON_RULESETS = ["p/python", "p/bandit", "p/secrets"]


def _wrap_py(code: str) -> str:
    """Ensure code is valid Python (adds pass if empty)."""
    code = code.strip()
    if not code:
        code = "pass"
    return code


def run_semgrep_batch(
    snippets: list[tuple[str, str]],  # (code, language)
    work_dir: str | None = None,
) -> list[list[dict[str, Any]]]:
    """Run Semgrep on a batch of code snippets.

    Returns per-snippet findings list.
    Only processes Python snippets (language == "python").
    """
    # Filter Python only
    py_indices = [i for i, (_, lang) in enumerate(snippets) if lang == "python"]
    if not py_indices:
        return [[] for _ in snippets]

    tmp = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="sg_"))
    tmp.mkdir(parents=True, exist_ok=True)
    cleanup = work_dir is None

    # Write snippets
    file_map: dict[str, int] = {}
    for idx in py_indices:
        code, _ = snippets[idx]
        wrapped = _wrap_py(code)
        h = hashlib.md5(wrapped.encode()).hexdigest()[:12]
        fname = f"fn_{h}.py"
        (tmp / fname).write_text(wrapped, encoding="utf-8")
        file_map[fname] = idx

    result: list[list[dict[str, Any]]] = [[] for _ in snippets]

    # Run each ruleset, merge findings
    for ruleset in PYTHON_RULESETS:
        try:
            proc = subprocess.run(
                ["semgrep", "scan", "--config", ruleset, "--json", "--no-git-ignore", str(tmp)],
                capture_output=True, text=True, timeout=120,
                cwd=str(tmp), encoding="utf-8", errors="replace",
            )
            if proc.returncode > 1:
                logger.warning(f"Semgrep {ruleset} exited {proc.returncode}: {proc.stderr[:100]}")
                continue
            data = json.loads(proc.stdout)
            for r in data.get("results", []):
                path = Path(r.get("path", "")).name
                idx = file_map.get(path)
                if idx is not None:
                    result[idx].append({
                        "rule": r.get("check_id", "?"),
                        "message": r.get("extra", {}).get("message", "")[:200],
                        "line": r.get("start", {}).get("line", "?"),
                        "severity": r.get("extra", {}).get("severity", "?"),
                    })
        except subprocess.TimeoutExpired:
            logger.warning(f"Semgrep {ruleset} timed out")
        except json.JSONDecodeError:
            logger.warning(f"Semgrep {ruleset} returned invalid JSON")
        except Exception as e:
            logger.warning(f"Semgrep {ruleset} failed: {e}")

    if cleanup:
        import shutil; shutil.rmtree(tmp, ignore_errors=True)

    return result
