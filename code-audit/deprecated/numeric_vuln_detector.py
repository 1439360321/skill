"""DEPRECATED: Regex-based numeric vulnerability detector.

Moved to deprecated/ on 2026-07-20.
Reason: regex pattern matching for integer overflow cannot distinguish between
safe and exploitable cases. It would bypass the entire LLM pipeline (static
decision returned "vuln" directly), skipping all 3 agents. The 3-agent
architecture handles this better via blind-spot scanning.

Kept for reference in case a lightweight pre-check is needed in the future.
"""

import re
from typing import Optional, Tuple


def check_numeric_vulnerability(code: str) -> Tuple[Optional[str], str, float]:
    """Check for integer overflow patterns in allocation and size calculations.

    Returns (vuln_type, reason, confidence) or (None, "", 0.0).
    """
    patterns = [
        (r'\(\s*\w+\s*\)\s*malloc\s*\(\s*\w+\s*\*\s*sizeof', "malloc_overflow",
         "Potential integer overflow in malloc(size * sizeof(...))"),
        (r'malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)', "malloc_overflow",
         "Potential integer overflow in malloc(var1 * var2)"),
        (r'calloc\s*\(\s*\w+\s*,\s*\w+\s*\*', "calloc_overflow",
         "Potential overflow in calloc with computed size"),
        (r'realloc\s*\(\s*\w+\s*,\s*\w+\s*\*\s*\w+\s*\)', "realloc_overflow",
         "Potential overflow in realloc with computed size"),
        (r'for\s*\(\s*\w+\s*=\s*\d+\s*;\s*\w+\s*<=\s*\w+\s*;', "loop_overflow",
         "Loop with <= bound (potential off-by-one)"),
        (r'\[\s*\w+\s*\+\s*\w+\s*\]', "array_overflow",
         "Array index with addition (potential overflow)"),
        (r'sizeof\s*\(\s*\w+\s*\)\s*\*\s*\d+\s*\+\s*\w+', "size_overflow",
         "Size calculation with addition after multiply"),
    ]

    for pattern, vuln_type, reason in patterns:
        if re.search(pattern, code):
            return (vuln_type, reason, 0.85)

    return (None, "", 0.0)
