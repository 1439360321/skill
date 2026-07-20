"""AST-based code slicer with data-flow and sanitization awareness.

Upgraded from the original VulnRAG-Audit slicer:
- Instead of flagging every function that *contains* a sink, it checks
  whether a source variable actually reaches the sink (dataflow).
- Sanitization patterns are detected and reported.
- Each slice now carries a risk-level assessment.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tree_sitter import Language, Parser

import tree_sitter_c as ts_c
import tree_sitter_python as ts_py

from src.scanner.dataflow import DataFlowAnalyzer
from src.scanner.sanitization import SanitizationDetector
from src.scanner.sink_registry import SINKS, get_risk_level
from src.utils.logger import setup_logger

logger = setup_logger()

# Try to import Java grammar — gracefully degrade if unavailable
try:
    import tree_sitter_java as ts_java

    _HAS_JAVA = True
except ImportError:
    _HAS_JAVA = False


class CodeSlicer:
    """Extract code slices with data-flow and sanitization context."""

    def __init__(self) -> None:
        self.c_lang = Language(ts_c.language())
        self.py_lang = Language(ts_py.language())
        self.parsers: dict[str, Parser] = {
            "c": Parser(self.c_lang),
            "python": Parser(self.py_lang),
        }
        if _HAS_JAVA:
            self.java_lang = Language(ts_java.language())
            self.parsers["java"] = Parser(self.java_lang)

        self.sink_functions: dict[str, dict[str, list[str]]] = SINKS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def slice_code(
        self,
        code: str,
        language: str,
        *,
        enable_dataflow: bool = True,
        enable_sanitization: bool = True,
    ) -> list[dict[str, Any]]:
        """Slice *code* and return suspicious slices with enriched metadata."""
        if language not in self.parsers:
            logger.warning(f"Unsupported language: {language}")
            return []

        parser = self.parsers[language]
        tree = parser.parse(bytes(code, "utf8"))
        root = tree.root_node

        df_analyzer = DataFlowAnalyzer(language) if enable_dataflow else None
        san_detector = SanitizationDetector(language) if enable_sanitization else None

        slices: list[dict[str, Any]] = []
        func_nodes = self._find_nodes(root, "function_definition")
        if not func_nodes:
            func_nodes = [root]

        # Also scan ERROR nodes for sink calls — truncated or incomplete C code
        # causes tree-sitter to produce ERROR nodes that may contain real
        # function calls (e.g., memmove inside a mid-cut if-statement).
        error_nodes = self._find_nodes(root, "ERROR")
        for err_node in error_nodes:
            # Only include ERROR nodes that are NOT inside a function_definition
            # (those are already covered by func_node scanning)
            inside_func = any(
                fn.start_byte <= err_node.start_byte and err_node.end_byte <= fn.end_byte
                for fn in func_nodes
            )
            if not inside_func and err_node.end_byte - err_node.start_byte > 10:
                func_nodes.append(err_node)

        for func_node in func_nodes:
            func_code = code[func_node.start_byte:func_node.end_byte]
            func_name = self._extract_function_name(func_node, language, code)

            # Check for sink functions
            sink_info = self._find_sink_in_function(func_node, func_code, language)

            line_start = (
                func_node.start_point[0] + 1
                if func_node.type != "translation_unit"
                else 1
            )
            line_end = (
                func_node.end_point[0] + 1
                if func_node.type != "translation_unit"
                else code.count("\n") + 1
            )

            if not sink_info:
                # No known sink pattern — emit full-function slice for LLM review.
                # Many real vulnerabilities (UAF, race condition, OOB, off-by-one)
                # don't involve standard library sinks. Per FuncVul/MoCQ/IRIS 2025:
                # pass all functions to LLM, not just sink-matched ones.
                slices.append({
                    "function_name": func_name,
                    "code": func_code,
                    "language": language,
                    "line_start": line_start,
                    "line_end": line_end,
                    "sink_type": None,
                    "sink_category": "generic",
                    "risk_level": "medium",
                    "has_sanitization": False,
                    "sanitization_detail": "",
                    "sanitization_confidence": 0.0,
                    "source_var": "",
                    "source_type": "unknown",
                    "dataflow_path": "",
                    "ast_confidence": 0.0,
                    "code_patterns": [],  # populated by codeql_runner in eval scripts
                })
                continue

            # Data-flow and sanitization use the ORIGINAL code (full file),
            # NOT func_code, because tree-sitter byte offsets are relative
            # to the original parse input. Passing func_code causes double-
            # slicing and incorrect byte ranges.
            df_result = None
            if df_analyzer:
                df_result = df_analyzer.analyze(func_node, code)

            # Dataflow is advisory: it adjusts confidence but never hard-filters.
            # Hard filtering caused 17 slices (including true positives) to be
            # dropped. The sanitization layer is the real FP reducer.

            # Sanitization detection — uses original code for correct offsets
            san_result = {"has_sanitization": False, "details": [], "confidence": 0.0}
            if san_detector:
                san_result = san_detector.detect_in_function(func_node, code)

            # Risk assessment
            risk_level = self._assess_risk(
                sink_info["category"],
                df_result,
                san_result,
            )

            slice_data: dict[str, Any] = {
                "function_name": func_name,
                "code": func_code,
                "language": language,
                "line_start": line_start,
                "line_end": line_end,
                "sink_type": sink_info["function"],
                "sink_category": sink_info["category"],
                "risk_level": risk_level,
                "has_sanitization": san_result["has_sanitization"],
                "sanitization_detail": "; ".join(san_result["details"])
                if san_result["details"]
                else "",
                "sanitization_confidence": san_result["confidence"],
                "code_patterns": [],  # populated by codeql_runner in eval scripts
            }

            if df_result:
                slice_data.update(
                    {
                        "source_var": df_result["source_var"],
                        "source_type": df_result["source_type"],
                        "dataflow_path": df_result["dataflow_path"],
                        "ast_confidence": self._calc_ast_confidence(
                            df_result,
                            san_result,
                        ),
                    }
                )
            else:
                slice_data.update(
                    {
                        "source_var": "",
                        "source_type": "unknown",
                        "dataflow_path": f"? → {sink_info['function']}",
                        "ast_confidence": 0.3,  # low — no dataflow evidence
                    }
                )

            slices.append(slice_data)

        return slices

    def slice_file(
        self,
        file_path: str,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Slice a source file from disk."""
        path = Path(file_path)
        ext = path.suffix.lower()
        lang_map = {".c": "c", ".h": "c", ".py": "python", ".java": "java"}
        language = lang_map.get(ext)
        if not language:
            return []
        code = path.read_text(encoding="utf-8-sig", errors="ignore")
        return self.slice_code(code, language, **kwargs)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_sink_in_function(
        self,
        func_node: Any,
        code: str,
        language: str,
    ) -> dict[str, str] | None:
        """Return the highest-risk sink found in the function.

        Priority: risk_level (high > medium > low) then length (longer first
        to avoid ``exec`` matching inside ``cursor.execute``).
        """
        # Collect all called function names from the AST
        called_functions: set[str] = set()
        self._collect_calls(func_node, called_functions)

        risk_order = {"high": 0, "medium": 1, "low": 2}
        candidates: list[tuple[int, int, str, str]] = []  # (risk_prio, -len, func, cat)
        for category, functions in self.sink_functions.get(language, {}).items():
            for func_name in functions:
                if func_name in called_functions:
                    risk = get_risk_level(category)
                    prio = risk_order.get(risk, 1)
                    candidates.append((prio, -len(func_name), func_name, category))
        # Lowest risk_prio (high first), then longest match (most negative -len)
        candidates.sort()
        if candidates:
            _, _, func_name, category = candidates[0]
            return {"function": func_name, "category": category}
        return None

    @staticmethod
    def _collect_calls(node: Any, called: set[str]) -> None:
        """Recursively collect function names from call_expression nodes."""
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node:
                name = CodeSlicer._resolve_call_name(func_node)
                if name:
                    called.add(name)
        for child in node.children:
            CodeSlicer._collect_calls(child, called)

    @staticmethod
    def _resolve_call_name(func_node: Any) -> str | None:
        """Resolve the function name from a call_expression's function child."""
        if func_node.type == "identifier":
            return func_node.text.decode("utf8")
        if func_node.type == "field_expression":
            field = func_node.child_by_field_name("field")
            if field:
                return field.text.decode("utf8")
        return None

    def _assess_risk(
        self,
        sink_category: str,
        df_result: dict | None,
        san_result: dict,
    ) -> str:
        """Determine risk level based on sink, dataflow, and sanitization.

        Only sanitization patterns relevant to the sink category are counted.
        Category-specific strong signals always → "low". Higher confidence
        from relevant patterns also → "low". Other patterns are ignored.
        """
        base_risk = get_risk_level(sink_category)

        # Category-specific strong signals → definitely safe
        strong_signals = {
            "command_injection": ["shell_escape", "subprocess_list_args", "command_allowlist"],
            "sql_injection": ["parameterized_query", "prepared_statement"],
            "code_injection": ["exec_sandbox", "safe_parse", "safe_eval_ast_whitelist"],
            "buffer_overflow": ["length_check", "sizeof_bound", "sizeof_bound_reverse",
                              "numeric_bound", "size_guard",
                              "safe_strncpy", "safe_strncat", "safe_snprintf",
                              "scanf_bounded", "memcpy_sizeof", "strncat_bounded",
                              "snprintf_bounded"],
            "path_traversal": ["path_normalize"],
            "deserialization": ["safe_parse"],
            "format_string": ["printf_format_literal"],  # only literal format string is safe
            "credential_hardcoding": ["env_var_credential"],
            "memory_corruption": ["null_check", "null_check_ptr", "ptr_null_guard_early_return",
                                "safe_free"],
            "ssrf": ["input_validation"],
            "xss": ["html_escape", "output_encoding"],
            "integer_overflow": ["size_guard", "numeric_bound", "length_check",
                               "ptr_null_guard_early_return"],
        }
        # All patterns that are potentially relevant to each category
        relevant_patterns = {
            "command_injection": strong_signals["command_injection"] + ["allowlist_check", "strip", "regex_sanitize"],
            "sql_injection": strong_signals["sql_injection"],
            "code_injection": strong_signals["code_injection"] + ["allowlist_check"],
            "buffer_overflow": strong_signals["buffer_overflow"] + ["null_check", "safe_fgets"],
            "path_traversal": strong_signals["path_traversal"],
            "deserialization": strong_signals["deserialization"],
            "format_string": strong_signals["format_string"],
            "credential_hardcoding": strong_signals["credential_hardcoding"],
            "memory_corruption": strong_signals["memory_corruption"] + ["strchr_null_check",
                                "token_null_guard"],
            "ssrf": strong_signals["ssrf"],
            "xss": strong_signals["xss"],
            "integer_overflow": strong_signals["integer_overflow"] + ["null_check"],
        }

        if san_result.get("has_sanitization"):
            details = san_result.get("details", [])
            relevant = relevant_patterns.get(sink_category, [])
            # Only count sanitization patterns relevant to this sink category
            relevant_details = [d for d in details if d in relevant]
            relevant_conf = min(0.9, len(relevant_details) * 0.3) if relevant_details else 0.0

            strong = strong_signals.get(sink_category, [])
            has_strong = any(s in details for s in strong)

            if has_strong or relevant_conf >= 0.6:
                return "low"
            elif relevant_conf >= 0.3:
                risk_downgrade = {"high": "medium", "medium": "low", "low": "low"}
                base_risk = risk_downgrade.get(base_risk, base_risk)

        # No dataflow found → downgrade for missing evidence.
        # Categories where the sink IS the vulnerability (no external source needed):
        # memory_corruption (double-free, use-after-free), integer_overflow,
        # credential_hardcoding — these don't need a source→sink path.
        _self_contained = {"memory_corruption", "integer_overflow", "credential_hardcoding",
                           "format_string"}
        if df_result is None and sink_category not in _self_contained:
            risk_downgrade = {"high": "medium", "medium": "low", "low": "low"}
            base_risk = risk_downgrade.get(base_risk, base_risk)

        return base_risk

    def _calc_ast_confidence(self, df_result: dict, san_result: dict) -> float:
        """Heuristic confidence score from AST-level signals (0.0–1.0)."""
        score = 0.5  # baseline
        if df_result.get("dataflow_path") and "→" in df_result["dataflow_path"]:
            score += 0.2
        if df_result.get("source_var") and df_result["source_var"] != "unknown_var":
            score += 0.15
        if san_result.get("has_sanitization"):
            score -= 0.2  # less confident it's actually exploitable
        return round(max(0.0, min(1.0, score)), 2)

    # ------------------------------------------------------------------
    # AST utilities — same as original but self-contained
    # ------------------------------------------------------------------

    def _find_nodes(self, node: Any, node_type: str, results: list | None = None) -> list:
        if results is None:
            results = []
        if hasattr(node, "type") and node.type == node_type:
            results.append(node)
        if hasattr(node, "children"):
            for child in node.children:
                self._find_nodes(child, node_type, results)
        return results

    def _extract_function_name(
        self,
        func_node: Any,
        language: str,
        code: str,
    ) -> str:
        """Extract function name from a function_definition node."""
        if func_node.type == "translation_unit":
            return "<module>"
        if func_node.type == "ERROR":
            return "<parse_error>"
        if language == "c":
            for child in func_node.children:
                if child.type == "function_declarator":
                    for sub in child.children:
                        if sub.type == "identifier":
                            return sub.text.decode("utf8")
                elif child.type == "pointer_declarator":
                    # void *func_name(...) — func_declarator is nested
                    for sub in child.children:
                        if sub.type == "function_declarator":
                            for ssub in sub.children:
                                if ssub.type == "identifier":
                                    return ssub.text.decode("utf8")
                elif child.type == "init_declarator":
                    for sub in child.children:
                        if sub.type == "function_declarator":
                            for ssub in sub.children:
                                if ssub.type == "identifier":
                                    return ssub.text.decode("utf8")
        elif language in ("python", "java"):
            for child in func_node.children:
                if child.type == "identifier":
                    return child.text.decode("utf8")
        return "unknown"
