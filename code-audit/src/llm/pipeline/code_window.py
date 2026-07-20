"""Pluggable code window strategies."""
from __future__ import annotations


class SimpleCodeWindow:
    """Simple truncation: code[:max_chars]."""

    def __init__(self, params: dict):
        self.max_chars = params.get("simple_max_chars", 1500)

    def extract(self, slice_data: dict) -> str:
        return slice_data.get("code", "")[:self.max_chars]


class IRISCodeWindow:
    """IRIS-style: ±N lines around code_pattern line numbers, with fallback."""

    def __init__(self, params: dict):
        self.window_lines = params.get("iris_window_lines", 5)
        self.max_chars = params.get("iris_max_chars", 3000)
        self.fallback = SimpleCodeWindow({"simple_max_chars": params.get("iris_fallback_chars", 2000)})

    def extract(self, slice_data: dict) -> str:
        code = slice_data.get("code", "")
        patterns = slice_data.get("code_patterns", [])
        lines = code.split("\n")

        focus_lines: set = set()
        for p in patterns:
            for ln in (p.get("lines", []) or [p.get("line", 0)]):
                if ln and ln > 0:
                    focus_lines.add(ln)

        if focus_lines:
            seen: set = set()
            parts = []
            for fl in sorted(focus_lines):
                start = max(0, fl - 1 - self.window_lines)
                end = min(len(lines), fl + self.window_lines)
                for i in range(start, end):
                    if i not in seen:
                        seen.add(i)
                        parts.append(lines[i])
                parts.append(f"# --- focus line {fl} ---")
            result = "\n".join(parts)
            if len(result) > self.max_chars:
                result = result[:self.max_chars] + "\n# ... (truncated)"
            return result

        return self.fallback.extract(slice_data)


class DynamicCodeWindow:
    """Tool-signal-driven window: stronger signal → narrower window.

    - 2+ tools agree on same area → IRIS ±N lines (high confidence)
    - 1 tool found something       → medium window (3000 chars)
    - all tools silent             → full code (no guidance)
    """

    def __init__(self, params: dict):
        self.iris_window = params.get("dynamic_iris_lines", 5)
        self.medium_chars = params.get("dynamic_medium_chars", 3000)

    def extract(self, slice_data: dict) -> str:
        patterns = slice_data.get("code_patterns", [])
        code = slice_data.get("code", "")

        if not patterns:
            # All tools silent → full code
            return code

        # Count distinct tool sources
        sources: set[str] = set()
        for p in patterns:
            src = p.get("source", p.get("rule", ""))
            if src:
                sources.add(src)

        if len(sources) >= 2:
            # High tool consensus → IRIS narrow window
            iris = IRISCodeWindow({"iris_window_lines": self.iris_window,
                                   "iris_max_chars": 3000,
                                   "iris_fallback_chars": 2000})
            return iris.extract(slice_data)
        elif len(sources) == 1:
            # Single tool signal → medium window
            return code[:self.medium_chars]
        else:
            return code


def create_code_window(params: dict):
    """Factory: return strategy instance based on params."""
    mode = params.get("mode", "simple")
    if mode == "iris":
        return IRISCodeWindow(params)
    elif mode == "dynamic":
        return DynamicCodeWindow(params)
    return SimpleCodeWindow(params)
