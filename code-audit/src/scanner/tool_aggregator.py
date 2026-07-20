"""Multi-tool aggregator — runs all available static analyzers and normalizes results.

Produces a unified ToolReport consumed by Agent1 (tool integrator) without
reading the source code itself. Agent1 only sees tool signals, blind spots,
and consensus level — then decides window strategy and delegates to A2/A3.
"""

from __future__ import annotations

from typing import Any

from src.utils.logger import setup_logger

logger = setup_logger()

# Tool coverage matrix: which tool covers which vulnerability classes
TOOL_COVERAGE = {
    "codeslicer": {
        "covers": ["buffer_overflow", "command_injection", "code_injection",
                    "sql_injection", "path_traversal", "format_string",
                    "memory_corruption", "integer_overflow", "deserialization",
                    "race_condition"],
        "blind_spots": ["logic_flaws", "business_logic", "auth_bypass",
                         "cryptography_misuse", "configuration"],
        "strength": "sink_pattern_matching",
        "weakness": "no semantic understanding, no inter-procedural analysis",
    },
    "codeql": {
        "covers": ["buffer_overflow", "command_injection", "sql_injection",
                    "path_traversal", "format_string", "memory_corruption",
                    "integer_overflow", "race_condition", "null_dereference",
                    "resource_leak"],
        "blind_spots": ["business_logic", "auth_bypass", "cryptography_misuse"],
        "strength": "dataflow + taint tracking, inter-procedural",
        "weakness": "requires build, misses logic bugs without sink patterns",
    },
    "semgrep": {
        "covers": ["command_injection", "code_injection", "sql_injection",
                    "path_traversal", "deserialization", "cryptography_misuse",
                    "xss"],
        "blind_spots": ["memory_corruption", "integer_overflow", "race_condition",
                         "use_after_free", "double_free"],
        "strength": "fast pattern matching, many community rules",
        "weakness": "no dataflow, AST-level only, Python-focused rules",
    },
}

# Categories no current tool covers well
UNIVERSAL_BLIND_SPOTS = [
    "logic_flaws",          # e.g., incorrect bounds check logic
    "business_logic",       # e.g., missing auth check in specific path
    "TOCTOU",               # time-of-check-time-of-use
    "cryptography_misuse",  # weak cipher, hardcoded key
    "integer_overflow",     # subtle ones without obvious patterns
]


def aggregate(slice_data: dict, language: str,
              codeql_findings: list[dict] | None = None,
              semgrep_findings: list[dict] | None = None) -> dict:
    """Run CodeSlicer (fast, in-process) + merge external tool results.

    Returns a unified report dict consumed by Agent1's TOOL_INTEGRATOR_PROMPT.
    """
    findings: list[dict] = []
    tools_run: list[str] = []
    tools_failed: list[str] = []

    # --- CodeSlicer (always runs, zero cost) ---
    tools_run.append("codeslicer")

    cs_patterns = slice_data.get("code_patterns", [])
    sink_type = slice_data.get("sink_type")
    sink_category = slice_data.get("sink_category", "generic")
    risk_level = slice_data.get("risk_level", "low")

    if sink_type:
        findings.append({
            "tool": "codeslicer",
            "type": sink_category,
            "sink": sink_type,
            "risk": risk_level,
            "line": slice_data.get("line_start"),
            "message": f"Sink {sink_type} ({sink_category}), risk={risk_level}",
        })

    for p in cs_patterns:
        findings.append({
            "tool": p.get("source", "codeslicer"),
            "type": p.get("type", "unknown"),
            "line": p.get("line"),
            "message": p.get("description", ""),
        })

    # --- CodeQL ---
    if codeql_findings is not None:
        tools_run.append("codeql")
        for f in codeql_findings:
            findings.append({
                "tool": "codeql",
                "type": f.get("rule", "unknown"),
                "line": f.get("line"),
                "severity": f.get("level", "warning"),
                "message": f.get("message", ""),
            })
    elif language == "c":
        tools_failed.append("codeql (not run)")

    # --- Semgrep ---
    if semgrep_findings is not None:
        tools_run.append("semgrep")
        for f in semgrep_findings:
            findings.append({
                "tool": "semgrep",
                "type": f.get("check_id", f.get("rule", "unknown")),
                "line": f.get("line", f.get("start", {}).get("line")),
                "message": f.get("extra", {}).get("message", f.get("message", "")),
            })
    elif language == "python":
        tools_failed.append("semgrep (not run)")

    # --- Consensus analysis ---
    consensus = _analyze_consensus(findings)

    # --- Blind spot analysis ---
    blind_spots = _identify_blind_spots(findings, tools_run, language)

    return {
        "tools_run": tools_run,
        "tools_failed": tools_failed,
        "findings": findings,
        "finding_count": len(findings),
        "consensus": consensus,
        "blind_spots": blind_spots,
        "sink": sink_type or "none",
        "sink_category": sink_category,
        "risk_level": risk_level,
        "language": language,
        "has_sanitization": slice_data.get("has_sanitization", False),
        "sanitization_detail": slice_data.get("sanitization_detail", ""),
    }


def _analyze_consensus(findings: list[dict]) -> dict:
    """Determine tool agreement level."""
    if not findings:
        return {"level": "no_signal", "agreed_area": None, "tool_count": 0}

    tools = set(f["tool"] for f in findings)
    types = set(f["type"] for f in findings)

    if len(tools) >= 2 and _tools_agree(findings):
        return {
            "level": "high",
            "agreed_area": max(set(f["type"] for f in findings), key=lambda t: sum(1 for f in findings if f["type"] == t)),
            "tool_count": len(tools),
            "detail": f"{len(tools)} tools agree on sink area",
        }

    if len(tools) == 1 and len(findings) >= 2:
        return {
            "level": "medium",
            "agreed_area": max(types, key=lambda t: sum(1 for f in findings if f["type"] == t)),
            "tool_count": 1,
            "detail": "single tool with multiple findings",
        }

    if len(tools) >= 2 and not _tools_agree(findings):
        return {
            "level": "conflict",
            "agreed_area": None,
            "tool_count": len(tools),
            "detail": f"tools disagree: {', '.join(sorted(types))}",
        }

    return {
        "level": "low",
        "agreed_area": max(types, key=lambda t: sum(1 for f in findings if f["type"] == t)) if types else None,
        "tool_count": len(tools),
        "detail": "single finding or weak signal",
    }


def _tools_agree(findings: list[dict]) -> bool:
    """Check if findings from different tools point to roughly the same area."""
    if len(findings) < 2:
        return False
    types = [f["type"] for f in findings]
    return len(set(types)) < len(types)  # at least one type overlap


def _identify_blind_spots(findings: list[dict], tools_run: list[str],
                          language: str) -> list[str]:
    """Determine which vulnerability classes no tool checked."""
    covered = set()
    for tool_name in tools_run:
        if tool_name in TOOL_COVERAGE:
            covered.update(TOOL_COVERAGE[tool_name]["covers"])

    # Add what tools actually found
    for f in findings:
        covered.add(f.get("type", ""))

    blind = [b for b in UNIVERSAL_BLIND_SPOTS if b not in covered]

    # Add tool-specific blind spots
    for tool_name in tools_run:
        if tool_name in TOOL_COVERAGE:
            for bs in TOOL_COVERAGE[tool_name]["blind_spots"]:
                if bs not in blind and bs not in covered:
                    blind.append(bs)

    return blind
