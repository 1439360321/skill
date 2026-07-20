"""Sanitization / input-validation detection on tree-sitter AST.

Searches for patterns that indicate the code already mitigates a potential
vulnerability — length checks, type casts, escaping, parameterised queries,
etc.  The result is used to lower the risk level of a slice and to skip
Stage-1 LLM triage when appropriate.
"""

from __future__ import annotations

import re
from typing import Any

from src.scanner.sink_registry import SANITIZATION_PATTERNS


class SanitizationDetector:
    """Check whether a code slice contains sanitization / validation."""

    def __init__(self, language: str):
        self.language = language
        self.patterns: list[tuple[str, str]] = SANITIZATION_PATTERNS.get(language, [])

    def detect(self, code: str) -> dict:
        """Run all patterns against *code* and return structured detection info.

        Returns:
            ``{"has_sanitization": bool, "details": [str, ...], "confidence": float}``
        """
        details: list[str] = []
        for pattern, label in self.patterns:
            try:
                if re.search(pattern, code):
                    details.append(label)
            except re.error:
                continue

        has = len(details) > 0
        # Confidence: more patterns → more confident (capped at 0.9)
        confidence = min(0.9, len(details) * 0.3) if has else 0.0

        return {
            "has_sanitization": has,
            "details": details,
            "confidence": round(confidence, 2),
        }

    def detect_in_function(
        self,
        func_node: Any,
        source_code: str,
    ) -> dict:
        """Run detection on the source text spanned by *func_node*."""
        if hasattr(func_node, "start_byte") and hasattr(func_node, "end_byte"):
            code = source_code[func_node.start_byte:func_node.end_byte]
        else:
            code = source_code
        return self.detect(code)

    def is_likely_safe(
        self,
        code: str,
        sink_category: str,
    ) -> bool:
        """Quick heuristic: is this code *probably* safe?

        Returns True when strong sanitization is detected for the given
        sink category — useful for filtering before LLM triage.
        """
        if not code:
            return False

        result = self.detect(code)
        if not result["has_sanitization"]:
            return False

        details = result["details"]

        # Strong sanitization → very likely safe
        strong_signals = {
            "sql_injection": ["parameterized_query", "prepared_statement"],
            "xss": ["html_escape", "output_encoding"],
            "code_injection": ["safe_parse", "ast.literal_eval"],
            "command_injection": ["subprocess_list_args", "shell_escape"],
            "buffer_overflow": ["length_check", "safe_snprintf", "safe_strncpy"],
            "path_traversal": ["path_normalize", "path_safe"],
            "deserialization": ["safe_parse"],
            "ssrf": ["input_validation"],
        }

        strong = strong_signals.get(sink_category, [])
        return any(s in details for s in strong)
