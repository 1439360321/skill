"""DEPRECATED: Regex-based safe pattern checker.

Moved to deprecated/ on 2026-07-20.
Reason: regex cannot understand code semantics. It would override LLM verdicts
based on fragile string matching (e.g., "no dangerous function calls = safe"
killed UAF/logic bug detections). The 3-agent architecture makes this obsolete.

Kept for reference in case a lightweight pre-filter is needed in the future.
"""

import re

SAFE_REPLACEMENTS = {
    "strcpy": "strncpy",
    "sprintf": "snprintf",
    "gets": "fgets",
    "vsprintf": "vsnprintf",
    "scanf": "fscanf",
}

ALL_DANGEROUS_SINKS = [
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
    "memcpy", "memmove", "printf", "fprintf", "dprintf",
    "system", "popen",
]


def _normalize_sink(sink_type: str) -> str:
    s = (sink_type or "").lstrip("_").lower()
    return s


def check_safe_pattern(code: str, sink_type: str) -> tuple:
    """Check if the sink usage matches a safe pattern.
    Returns (is_safe: bool, reason: str).
    """
    sink = _normalize_sink(sink_type) if sink_type else ""

    called_dangerous = []
    for func in ALL_DANGEROUS_SINKS:
        pattern = r'\b' + re.escape(func) + r'\s*\('
        if re.search(pattern, code):
            called_dangerous.append(func)

    if not called_dangerous:
        if sink and sink in ALL_DANGEROUS_SINKS:
            return (False, "")
        return (True, "no dangerous function calls found")

    for func in called_dangerous:
        if func in ("printf", "fprintf", "dprintf"):
            m = re.search(r'\b' + re.escape(func) + r'\s*\(\s*"', code)
            if m:
                continue

        if func in ("system", "popen"):
            call_match = re.search(r'\b' + re.escape(func) + r'\s*\(\s*"([^"]*)"', code)
            if call_match:
                cmd_str = call_match.group(1)
                if '%' not in cmd_str:
                    continue

        if func in ("memcpy", "memmove"):
            m = re.search(r'\b' + re.escape(func) + r'\s*\([^,]+,[^,]+,\s*sizeof\s*\(', code)
            if m:
                continue

        if func == sink:
            return (False, "")

    if called_dangerous:
        return (True, f"all {len(called_dangerous)} dangerous calls use safe patterns")

    return (False, "")
