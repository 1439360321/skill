"""CodeQL runner — batch analysis with --build-mode=none for single functions.

Replaces hand-written tree-sitter patterns with GitHub's 61 pre-built C/C++
security queries.  One CodeQL invocation per batch of functions.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import hashlib
from pathlib import Path
from typing import Any

from src.utils.logger import setup_logger

logger = setup_logger()

# Locate CodeQL CLI — checked at import time, cached per process
_CODEQL_BIN: str | None = None


def _find_codeql() -> str | None:
    """Locate the CodeQL CLI binary.  Searches common locations."""
    global _CODEQL_BIN
    if _CODEQL_BIN is not None:
        return _CODEQL_BIN or None

    candidates = [
        "codeql",  # on PATH
    ]
    # Also search relative to the project root (where we extracted it)
    cur = Path(__file__).resolve().parent
    for _ in range(5):
        bundled = cur / "codeql" / "codeql" / "codeql"
        if bundled.exists():
            candidates.insert(0, str(bundled))
        bundled = cur / "codeql" / "codeql" / "codeql.exe"
        if bundled.exists():
            candidates.insert(0, str(bundled))
        cur = cur.parent

    for c in candidates:
        try:
            result = subprocess.run(
                [c, "--version"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                _CODEQL_BIN = c
                logger.info(f"CodeQL found: {c}")
                return c
        except Exception:
            continue

    logger.warning("CodeQL not found — code_patterns will be empty")
    return None


# Wrapper adds 7 includes + 1 blank line before user code
_CODEQL_LINE_OFFSET = 8

_WRAP_HEADER = (
    "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
    "#include <unistd.h>\n#include <fcntl.h>\n#include <stdint.h>\n"
    "#include <stddef.h>\n\n"
)


def _wrap_c(code: str) -> str:
    """Minimal C wrapper so the single function can be parsed by CodeQL."""
    return _WRAP_HEADER + code


def _parse_sarif(sarif_path: str) -> dict[str, list[dict[str, Any]]]:
    """Parse SARIF output → {filename: [findings]}. Adjusts line numbers for wrapper offset."""
    with open(sarif_path, encoding="utf-8") as f:
        data = json.load(f)

    results: dict[str, list[dict[str, Any]]] = {}
    for run in data.get("runs", []):
        for r in run.get("results", []):
            rule_id = r.get("ruleId", "?")
            message = r.get("message", {}).get("text", "")
            level = r.get("level", "warning")
            for loc in r.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                raw_line = region.get("startLine", 0)
                col = region.get("startColumn")

                # Subtract wrapper header lines to get original code line
                adjusted_line = max(1, (raw_line or 1) - _CODEQL_LINE_OFFSET)

                if artifact not in results:
                    results[artifact] = []
                results[artifact].append({
                    "rule": rule_id,
                    "message": message[:200],
                    "line": adjusted_line,
                    "column": col,
                    "level": level,
                    "source": "codeql",
                })
    return results


def run_codeql_batch(
    snippets: list[tuple[str, str]],  # (code, language)
    work_dir: str | None = None,
) -> list[list[dict[str, Any]]]:
    """Run CodeQL on a batch of code snippets. Returns per-snippet findings.

    Args:
        snippets: list of (code, language). Only C is supported currently.
        work_dir: temp directory to use. Created if None.

    Returns:
        list of lists — findings[i] for snippets[i]
    """
    codeql = _find_codeql()
    if codeql is None:
        return [[] for _ in snippets]

    # Filter to C only (CodeQL --build-mode=none needs C grammar)
    c_indices = [i for i, (_, lang) in enumerate(snippets) if lang == "c"]
    if not c_indices:
        return [[] for _ in snippets]

    # Write snippets to temp directory
    if work_dir:
        tmp = Path(work_dir)
        tmp.mkdir(parents=True, exist_ok=True)
        cleanup = False
    else:
        tmp = Path(tempfile.mkdtemp(prefix="codeql_"))
        cleanup = True

    db_dir = tmp / "db"
    sarif_out = tmp / "results.sarif"

    # Map: filename → snippet index
    file_map: dict[str, int] = {}
    total_files = 0
    for idx in c_indices:
        code, _ = snippets[idx]
        wrapped = _wrap_c(code)
        # Use hash for unique filename, avoid overwriting duplicates
        h = hashlib.md5(wrapped.encode()).hexdigest()[:12]
        fname = f"fn_{h}.c"
        (tmp / fname).write_text(wrapped, encoding="utf-8")
        file_map[fname] = idx
        total_files += 1

    logger.info(f"CodeQL: {total_files} files in {tmp}")

    try:
        # Create database
        result = subprocess.run(
            [codeql, "database", "create", str(db_dir),
             "--language=cpp", f"--source-root={tmp}",
             "--build-mode=none", "--overwrite"],
            capture_output=True, text=True, timeout=120,
            cwd=str(tmp),
        )
        if result.returncode != 0:
            logger.warning(f"CodeQL DB creation failed: {result.stderr[:200]}")
            if cleanup:
                import shutil; shutil.rmtree(tmp, ignore_errors=True)
            return [[] for _ in snippets]

        # Run analysis
        result = subprocess.run(
            [codeql, "database", "analyze", str(db_dir),
             "codeql/cpp-queries",
             "--format=sarif-latest", f"--output={sarif_out}"],
            capture_output=True, text=True, timeout=300,
            cwd=str(tmp),
        )
        if result.returncode != 0:
            logger.warning(f"CodeQL analysis failed: {result.stderr[:200]}")
            if cleanup:
                import shutil; shutil.rmtree(tmp, ignore_errors=True)
            return [[] for _ in snippets]

        # Parse results
        all_findings = _parse_sarif(str(sarif_out))
    except subprocess.TimeoutExpired:
        logger.warning("CodeQL timed out")
        all_findings = {}
    except Exception as e:
        logger.warning(f"CodeQL failed: {e}")
        all_findings = {}

    # Map back to original snippet order
    result: list[list[dict[str, Any]]] = [[] for _ in snippets]
    for fname, findings in all_findings.items():
        idx = file_map.get(fname)
        if idx is not None:
            result[idx] = findings

    if cleanup:
        import shutil; shutil.rmtree(tmp, ignore_errors=True)

    return result
