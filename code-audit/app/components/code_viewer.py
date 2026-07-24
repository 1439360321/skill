"""Code viewer — syntax-highlighted code with vulnerability line markers."""
from __future__ import annotations

import streamlit as st


def render_code(code: str, language: str = "c", highlight_lines: list[int] | None = None) -> None:
    """Display code with optional line highlighting for vulnerable regions.

    Args:
        code: Source code string.
        language: Programming language for syntax highlighting.
        highlight_lines: Line numbers (1-indexed) to highlight in red.
    """
    if not code:
        st.caption("（无代码）")
        return

    # Build line-numbered output
    lines = code.split("\n")
    if highlight_lines:
        hl_set = set(highlight_lines)
    else:
        hl_set = set()

    # Use markdown with inline HTML for line highlighting
    output_lines: list[str] = []
    for i, line in enumerate(lines[:300]):  # cap at 300 lines
        ln = i + 1
        prefix = f"{ln:4d} | "
        if ln in hl_set:
            output_lines.append(f"<span style='background-color:#ff4b4b33'>{prefix}{_escape_html(line)}</span>")
        else:
            output_lines.append(f"{prefix}{_escape_html(line)}")

    truncated = len(lines) > 300
    if truncated:
        output_lines.append(f"... ({len(lines) - 300} more lines)")

    html = "<pre style='font-size:13px;line-height:1.4;overflow-x:auto'>" + "\n".join(output_lines) + "</pre>"
    st.markdown(html, unsafe_allow_html=True)


def render_code_simple(code: str, language: str = "c", max_lines: int = 200) -> None:
    """Simple code display via st.code — no line highlighting."""
    lines = code.split("\n")
    numbered = "\n".join(f"{i+1:4d} | {l}" for i, l in enumerate(lines[:max_lines]))
    st.code(numbered, language=language if language in ("python", "c", "java") else None)


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
