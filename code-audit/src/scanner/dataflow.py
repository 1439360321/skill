"""Lightweight Source→Sink data-flow path tracking on tree-sitter AST.

Operates within a single function only — does NOT perform inter-procedural
analysis.  Variable assignment chains are followed, but pointer / alias
analysis is deliberately excluded for complexity reasons.
"""

from __future__ import annotations

from typing import Any

from src.scanner.sink_registry import SOURCES, SINKS, get_risk_level


class DataFlowAnalyzer:
    """Track data flow from sources to sinks within a single function AST."""

    def __init__(self, language: str):
        self.language = language
        self.sources = SOURCES.get(language, {})
        self.sinks = SINKS.get(language, {})

    def analyze(
        self,
        func_node: Any,
        source_code: str,
    ) -> dict | None:
        """Analyze a function node and return data-flow info if a source→sink
        path is found, or *None* when no such path exists.
        """
        source_vars = self._find_source_vars(func_node, source_code)
        if not source_vars:
            return None

        sink_info = self._find_reachable_sink(func_node, source_vars, source_code)
        if sink_info is None:
            return None

        var_name, sink_func, sink_category = sink_info
        flow_path = self._build_flow_path(var_name, sink_func, source_vars, source_code)

        return {
            "source_var": var_name,
            "source_type": source_vars.get(var_name, "unknown"),
            "sink_function": sink_func,
            "sink_category": sink_category,
            "dataflow_path": flow_path,
            "risk_level": get_risk_level(sink_category),
            "all_sources": list(source_vars.keys()),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_source_vars(self, func_node: Any, code: str) -> dict[str, str]:
        """Walk the function AST to find variable→source_type mappings.

        Also tracks indirect dataflow: source → helper call return → variable.
        """
        found: dict[str, str] = {}

        # Function-call sources (e.g. input(), recv())
        call_nodes: list[Any] = []
        self._collect_nodes(func_node, "call_expression", call_nodes)
        for call in call_nodes:
            name = self._call_name(call, code)
            if name and name in self.sources.get("function_calls", []):
                source_type = name
                parent = call.parent if hasattr(call, "parent") else None
                if parent and parent.type == "assignment":
                    lhs = self._lhs_of_assignment(parent, code)
                    if lhs:
                        found[lhs] = f"function:{source_type}"

        # Object-attribute sources (Python/Java)
        if self.language in ("python", "java"):
            for child in self._walk_tree(func_node):
                node_text = code[child.start_byte:child.end_byte] if hasattr(child, "start_byte") else ""
                for obj in self.sources.get("objects", []):
                    if obj in node_text:
                        found[self._nearest_var_name(child, code)] = f"object:{obj}"
                        break

        # Variable sources from function parameters (C: argv)
        for child in self._walk_tree(func_node):
            if child.type == "identifier":
                var_text = code[child.start_byte:child.end_byte]
                if var_text in self.sources.get("variables", []):
                    found[var_text] = "parameter_source"

        # Function parameters ARE potential sources (external input)
        for param_node_type in ("parameter_list", "parameters"):
            param_list = self._find_child(func_node, param_node_type)
            if param_list:
                for child in self._walk_tree(param_list):
                    if child.type == "identifier":
                        pname = code[child.start_byte:child.end_byte]
                        if pname not in found:
                            found[pname] = "function_parameter"
                break

        # Cross-function dataflow (1 level): source → helper(args) → result → sink
        self._track_cross_function_flow(func_node, found, code)

        return found

    def _track_cross_function_flow(
        self,
        func_node: Any,
        source_vars: dict[str, str],
        code: str,
    ) -> None:
        """Lightweight 1-level inter-procedural tracking.

        When a source variable is passed to a helper function call and the
        result is assigned to a variable, that result variable is also marked
        as source-derived (e.g. ``source→helper→result``).
        """
        assignments = []
        self._collect_nodes(func_node, "assignment", assignments)

        # Also collect augmented assignments and variable declarations (C)
        decls = []
        self._collect_nodes(func_node, "init_declarator", decls)

        all_assigns = assignments + decls

        for assign in all_assigns:
            lhs = self._lhs_of_assignment(assign, code)
            if not lhs:
                continue

            # Find call nodes in the RHS of this assignment
            rhs_calls: list[Any] = []
            self._collect_nodes(assign, "call_expression", rhs_calls)
            self._collect_nodes(assign, "call", rhs_calls)

            for call in rhs_calls:
                call_name = self._call_name(call, code)
                if not call_name:
                    continue
                # Skip if this call is itself a known sink (already handled)
                is_sink = any(
                    call_name == f.rstrip("(")
                    for flist in self.sinks.values()
                    for f in flist
                )
                if is_sink:
                    continue
                # Check if any SOURCE variable is passed as argument to this helper
                for var_name in source_vars:
                    if self._var_in_call_args(call, var_name, code):
                        # source → helper() → lhs — mark lhs as indirect source
                        if lhs not in source_vars:
                            source_vars[lhs] = f"cross_function:{var_name}→{call_name}"
                        break

    def _find_reachable_sink(
        self,
        func_node: Any,
        source_vars: dict[str, str],
        code: str,
    ) -> tuple[str, str, str] | None:
        """Check if any source variable reaches a sink function.

        Uses AST-level identifier matching (not substring) to avoid
        false matches like ``exec`` matching ``execute``.
        """
        call_nodes: list[Any] = []
        self._collect_nodes(func_node, "call_expression", call_nodes)
        self._collect_nodes(func_node, "call", call_nodes)

        for call in call_nodes:
            name = self._call_name(call, code)
            if not name:
                continue

            for category, functions in self.sinks.items():
                for fname in functions:
                    bare_fname = fname.rstrip("(")
                    if name == bare_fname or name == fname:
                        # AST-level check: does a source identifier appear in
                        # the argument sub-tree of this call?
                        for var in source_vars:
                            if self._var_in_call_args(call, var, code):
                                return (var, name, category)
                        # Even without direct variable match, if there are sources
                        # in the function and the sink is present, report it
                        if source_vars:
                            first_var = list(source_vars.keys())[0]
                            return (first_var, name, category)

        return None

    def _var_in_call_args(self, call_node: Any, var_name: str, code: str) -> bool:
        """Check if *var_name* appears as an identifier node in the call arguments.

        Uses AST traversal — not substring matching — to avoid ``exec``
        matching ``execute``, ``open`` matching ``fopen``, etc.
        """
        # Find the argument list child — tree-sitter uses "argument_list" (C)
        # or "arguments" (Python/Java)
        for child in call_node.children:
            if child.type in ("argument_list", "arguments"):
                return self._has_identifier(child, var_name, code)
        return False

    def _has_identifier(self, node: Any, var_name: str, code: str) -> bool:
        """Recursively check if *node* subtree contains an identifier matching *var_name*."""
        if hasattr(node, "type"):
            if node.type == "identifier":
                return code[node.start_byte:node.end_byte] == var_name
        if hasattr(node, "children"):
            for child in node.children:
                if self._has_identifier(child, var_name, code):
                    return True
        return False

    def _build_flow_path(
        self,
        var_name: str,
        sink_func: str,
        source_vars: dict[str, str],
        code: str,
    ) -> str:
        """Build a human-readable data-flow path string."""
        source_type = source_vars.get(var_name, "unknown")
        return f"{var_name} ({source_type}) → {sink_func}"

    # ------------------------------------------------------------------
    # AST navigation utilities
    # ------------------------------------------------------------------

    def _collect_nodes(self, node: Any, node_type: str, results: list) -> None:
        """Recursively collect nodes of a given type."""
        if hasattr(node, "type") and node.type == node_type:
            results.append(node)
        if hasattr(node, "children"):
            for child in node.children:
                self._collect_nodes(child, node_type, results)

    def _walk_tree(self, node: Any):
        """Yield every node in the AST subtree."""
        yield node
        if hasattr(node, "children"):
            for child in node.children:
                yield from self._walk_tree(child)

    def _call_name(self, call_node: Any, code: str) -> str | None:
        """Extract the function name from a call node."""
        for child in call_node.children:
            if child.type == "identifier":
                return code[child.start_byte:child.end_byte]
            if child.type == "attribute":
                return code[child.start_byte:child.end_byte]
        # Fallback
        func_text = code[call_node.start_byte:call_node.end_byte]
        paren = func_text.find("(")
        if paren > 0:
            return func_text[:paren].strip()
        return None

    def _lhs_of_assignment(self, assign_node: Any, code: str) -> str | None:
        """Get the left-hand side variable name of an assignment."""
        for child in assign_node.children:
            if child.type == "identifier":
                return code[child.start_byte:child.end_byte]
            if child.type in ("assignment", "subscript", "attribute"):
                # Drill into left-hand side
                for sub in child.children:
                    if sub.type == "identifier":
                        return code[sub.start_byte:sub.end_byte]
        return None

    def _find_child(self, node: Any, target_type: str) -> Any | None:
        """Return the first direct child of *node* with the given type."""
        if hasattr(node, "children"):
            for child in node.children:
                if hasattr(child, "type") and child.type == target_type:
                    return child
        return None

    def _nearest_var_name(self, node: Any, code: str) -> str:
        """Find the nearest variable name near this AST node."""
        # Walk up to find enclosing assignment or declaration
        current = node
        while hasattr(current, "parent") and current.parent is not None:
            current = current.parent
            if current.type in ("assignment", "variable_declaration"):
                for child in current.children:
                    if child.type == "identifier":
                        return code[child.start_byte:child.end_byte]
        return "unknown_var"
