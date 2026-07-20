"""LLM output parser — extract JSON from model responses.

Graded for robustness: tries markdown code blocks first, then raw JSON,
then regex extraction as a fallback.
"""

from __future__ import annotations

import json
import re
from typing import Any

from src.utils.logger import setup_logger

logger = setup_logger()


class LLMOutputParser:
    """Parse LLM response text into structured vulnerability results."""

    @staticmethod
    def parse(response: str) -> dict[str, Any] | None:
        """Extract JSON dict from an LLM text response.

        Tries, in order:
        0. Strip ``<think>...</think>`` blocks (DeepSeek-R1 reasoning)
        1. Markdown code block with optional ``json`` tag
        2. The entire response as JSON
        3. Regex extraction of the first top-level brace-delimited object
        """
        if not response or not response.strip():
            return None

        # 0. Strip reasoning-model artifacts (DeepSeek-R1)
        # 0a. Closed <think>...</think> blocks
        response = re.sub(r"<think>[\s\S]*?</think>", "", response)
        # 0b. Unclosed <think> block — strip from <think> to end
        response = re.sub(r"<think>[\s\S]*$", "", response)
        # 0c. Standalone "<｜end▁of▁thinking｜>" / "Response" markers R1 sometimes emits
        response = re.sub(r"^\s*(?:response|Response)\s*\n?", "", response)
        response = response.strip()
        if not response:
            return None

        # 1. Markdown code block — with or without closing ```
        for m in re.finditer(r"```(?:json)?\s*([\s\S]*?)\s*```", response):
            try:
                return json.loads(m.group(1).strip())
            except json.JSONDecodeError:
                continue
        # 1b. Opening ```json but no closing ``` — try full response after stripping prefix
        m = re.match(r"```(?:json)?\s*\n?([\s\S]*)", response)
        if m:
            inner = m.group(1).strip()
            # Try extracting brace block from the code
            brace = re.search(r"\{[\s\S]*\}", inner)
            if brace:
                try:
                    return json.loads(brace.group())
                except json.JSONDecodeError:
                    pass

        # 2. Entire response
        try:
            return json.loads(response.strip())
        except json.JSONDecodeError:
            pass

        # 3. Regex — first brace-delimited block
        brace = re.search(r"\{[\s\S]*\}", response)
        if brace:
            try:
                return json.loads(brace.group())
            except json.JSONDecodeError:
                pass

        logger.warning(f"Failed to parse LLM response as JSON: {response[:200]}")
        return None

    @staticmethod
    def validate(result: dict[str, Any]) -> dict[str, Any]:
        """Validate and normalise a parsed result dict."""
        validated: dict[str, Any] = {
            "has_vulnerability": bool(result.get("has_vulnerability", False)),
            "vulnerability_type": str(result.get("vulnerability_type", "UNKNOWN")),
            "confidence": float(result.get("confidence", 0.0)),
            "description": str(result.get("description", "")),
            "line_numbers": result.get("line_numbers", []),
            "remediation": str(result.get("remediation", "")),
        }
        # Clamp confidence
        validated["confidence"] = round(max(0.0, min(1.0, validated["confidence"])), 4)

        # Normalise line numbers
        if isinstance(validated["line_numbers"], list):
            validated["line_numbers"] = [
                int(x)
                for x in validated["line_numbers"]
                if isinstance(x, (int, float, str))
                and str(x).strip().lstrip("-").isdigit()
            ]
        else:
            validated["line_numbers"] = []

        # Pass through extra fields (severity, CWE, etc.)
        for key in (
            "severity",
            "cwe_id",
            "exploitability",
            "impact",
            "reasoning_chain",
            "cwe_reference",
            "suspicious",
            "reason",
            "confirmed",
            "adjusted_confidence",
            "adjusted_severity",
            "false_positive_reason",
        ):
            if key in result:
                validated[key] = result[key]

        return validated

    @staticmethod
    def parse_and_validate(response: str) -> dict[str, Any] | None:
        """Parse + validate in one call.  Returns None on failure."""
        parsed = LLMOutputParser.parse(response)
        if parsed is None:
            return None
        return LLMOutputParser.validate(parsed)
