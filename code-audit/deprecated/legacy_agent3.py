"""DEPRECATED: Legacy Agent3 evidence collector + EVIDENCE_PROMPT.

Moved to deprecated/ on 2026-07-20.
Reason: V1/V2 used agent3_evidence() to collect line numbers and CWE IDs
after a vuln verdict. The new agent3_blind_spot() replaces this entirely —
it finds blind-spot vulnerabilities instead of just annotating existing ones.

Also includes the EVIDENCE_PROMPT template and legacy SafePatternsPostProcessor /
NumericVulnPostProcessor classes that were previously in post_processor.py.

Kept for reference — may be useful if a post-hoc evidence collection step
is needed without the full blind-spot scanning.
"""

import json
import re
from src.utils.logger import setup_logger

logger = setup_logger()

EVIDENCE_PROMPT = """Confirmed vulnerability: {cwe_category}
Verdict confidence: {confidence}

Source code:
```{language}
{code}
```

List the evidence:
1. Exact vulnerable line numbers
2. CWE reference
3. Brief remediation suggestion

Return raw JSON (no markdown):
{{"line_numbers":[start,end], "cwe_id":"CWE-XXX", "remediation":"brief fix suggestion"}}"""


def agent3_evidence(client, slice_data: dict, result: dict, params: dict) -> dict:
    """Legacy agent3: post-hoc evidence collection for confirmed vulns.

    Replaced by agent3_blind_spot() in the 3-agent architecture.
    """
    code = slice_data.get("code", "")
    lang = slice_data.get("language", "c")
    cwe_category = slice_data.get("sink_category", "unknown")
    confidence = result.get("final_confidence", 0.5)

    prompt = EVIDENCE_PROMPT.format(
        cwe_category=cwe_category,
        confidence=confidence,
        language=lang,
        code=code,
    )

    try:
        resp = client.generate(prompt, temperature=0.1, max_tokens=512)
        parsed = _parse_json(resp)
        if parsed:
            return parsed
    except Exception as e:
        logger.warning(f"Agent3 legacy failed: {e}")
    return {}


def _parse_json(text: str) -> dict | None:
    """Robust JSON parser (from original post_processor.py)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    m = re.search(r'\{[^{}]*"line_numbers"\s*:\s*\[[^\]]*\][^{}]*\}', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass

    m = re.search(r'\{.*\}', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass

    logger.warning(f"JSON parse failed: {text[:120]}")
    return None


# =========================================================================
# Legacy regex-based post-processors (pre-2026-07-20)
# =========================================================================

class SafePatternsPostProcessor:
    """DEPRECATED: LLM vuln but safe pattern detected → override to safe.

    Removed because regex cannot understand code semantics.
    "no dangerous function calls found" ≠ safe (UAF, logic bugs, race conditions).
    """

    def process(self, result: dict, slice_data: dict, params: dict) -> dict:
        if result.get("final_verdict") != "vuln":
            return result
        try:
            from deprecated.safe_patterns import check_safe_pattern
            code = slice_data.get("code", "")
            sink_type = (slice_data.get("sink_type") or "").lstrip("_").lower()
            if not sink_type:
                return result
            is_safe, safe_reason = check_safe_pattern(code, sink_type)
            if is_safe:
                result["final_verdict"] = "safe"
                result["final_method"] = result.get("final_method", "") + "_safe_pattern_override"
                result["final_confidence"] = max(result.get("final_confidence", 0.5) - 0.2, 0.3)
                result["llm_reasoning"] = (result.get("llm_reasoning", "") +
                                           f" [SAFE PATTERN: {safe_reason}]")
        except ImportError:
            pass
        return result


class NumericVulnPostProcessor:
    """DEPRECATED: LLM safe but numeric vuln detected → override to vuln.

    Removed because regex patterns produce too many false positives and
    cannot distinguish safe from exploitable integer operations.
    """

    def process(self, result: dict, slice_data: dict, params: dict) -> dict:
        if result.get("final_verdict") != "safe":
            return result
        try:
            from deprecated.numeric_vuln_detector import check_numeric_vulnerability
            code = slice_data.get("code", "")
            if code:
                vuln_type, reason, confidence = check_numeric_vulnerability(code)
                if vuln_type:
                    result["final_verdict"] = "vuln"
                    result["final_method"] = result.get("final_method", "") + "_numeric_vuln_override"
                    result["final_confidence"] = confidence
                    result["vulnerability_type"] = f"CWE-190-{vuln_type}"
                    result["llm_reasoning"] = (result.get("llm_reasoning", "") +
                                               f" [NUMERIC VULN: {reason}]")
        except ImportError:
            pass
        return result
