"""Prompt builder for three-stage LLM vulnerability detection.

Stage 1 — Quick triage (low temperature, short output)
Stage 2 — CoT deep analysis with RAG context
Stage 3 — Self-verification / false-positive review
"""

from __future__ import annotations

from typing import Any


class PromptBuilder:
    """Build structured prompts for each stage of the detection pipeline."""

    # ------------------------------------------------------------------
    # Stage 1 — Quick triage
    # ------------------------------------------------------------------

    STAGE1_TEMPLATE = """You are a code security triage specialist. Quickly determine if this code MIGHT contain a security vulnerability.

【Code】
```{language}
{code}
```

Rules:
- If the code clearly sanitizes input (length check, type casting, parameterized query), return "suspicious": false
- If the code uses wrapper/helper functions that are known to be safe, return false
- If unsure, return true (err on the side of caution)
- Only return false if you are VERY confident the code is safe

Return ONLY this JSON (no other text):
{{"suspicious": true or false, "reason": "one short sentence"}}"""

    # ------------------------------------------------------------------
    # Stage 2 — Deep analysis
    # ------------------------------------------------------------------

    STAGE2_TEMPLATE = """You are a senior code security auditor. Perform a thorough vulnerability analysis.

【Static Analysis Context】
- Language: {language}
- Sink Function: {sink_type} ({sink_category})
- Data Source: {source_var} ({source_type})
- Data Flow: {dataflow_path}
- Sanitization Detected: {sanitization_info}
- AST Risk Level: {risk_level}

{retrieved_section}

{few_shot_section}

【Code to Analyze】
```{language}
{code}
```

Think step by step:
1. TRACE the data flow from source to sink. Is user input actually reachable?
2. CHECK sanitization. Is it sufficient? Can it be bypassed? How?
3. If the vulnerability is real, what is the IMPACT (confidentiality/integrity/availability)?
4. CLASSIFY the vulnerability with the correct CWE ID.
5. RECOMMEND a specific, actionable fix.

Return ONLY this JSON (no other text):
{{
  "has_vulnerability": true or false,
  "vulnerability_type": "CWE-XXX",
  "cwe_id": "CWE-XXX",
  "confidence": 0.0 to 1.0,
  "severity": "HIGH" or "MEDIUM" or "LOW" or "INFO",
  "exploitability": "EASY" or "MODERATE" or "DIFFICULT" or "NONE",
  "impact": "description of potential real-world impact",
  "description": "Detailed description of the vulnerability",
  "reasoning_chain": {{
    "step1_dataflow": "trace the flow...",
    "step2_sanitization": "assess mitigations...",
    "step3_impact": "assess real-world harm..."
  }},
  "line_numbers": [int, int],
  "remediation": "specific code fix recommendation",
  "cwe_reference": "https://cwe.mitre.org/data/definitions/XXX.html"
}}"""

    # ------------------------------------------------------------------
    # Stage 3 — Self-verification
    # ------------------------------------------------------------------

    STAGE3_TEMPLATE = """Review this vulnerability finding for potential false positives.

【Original Finding】
{{
  "has_vulnerability": {has_vulnerability},
  "vulnerability_type": "{vulnerability_type}",
  "confidence": {confidence},
  "severity": "{severity}",
  "description": "{description}"
}}

【Original Code】
```{language}
{code}
```

Challenge each conclusion rigorously:
1. Is the data source TRULY attacker-controllable? Could it come from a trusted internal source?
2. Can the sanitization ACTUALLY be bypassed? If yes, explain specifically how (with example input).
3. Would this cause REAL harm in practice, or is it a theoretical/contrived issue?
4. Is the severity assessment accurate? Consider authentication requirements and real-world exploitability.
5. Is the CWE classification correct? Check if a more specific or different CWE applies.

Return ONLY this JSON (no other text):
{{
  "confirmed": true or false,
  "adjusted_confidence": 0.0 to 1.0,
  "adjusted_severity": "HIGH" or "MEDIUM" or "LOW" or "INFO",
  "false_positive_reason": "if not confirmed, explain specifically why this is NOT a real vulnerability",
  "refined_description": "updated description applying any corrections"
}}"""

    # ------------------------------------------------------------------
    # Build methods
    # ------------------------------------------------------------------

    @classmethod
    def build_stage1(cls, code: str, language: str) -> str:
        return cls.STAGE1_TEMPLATE.format(code=code, language=language)

    @classmethod
    def build_stage2(
        cls,
        code: str,
        language: str,
        slice_data: dict,
        retrieved_cases: list[dict],
        few_shot_text: str = "",
    ) -> str:
        # RAG section
        retrieved_section = ""
        if retrieved_cases:
            parts = ["【Similar Historical Vulnerability Cases】"]
            for i, case in enumerate(retrieved_cases[:5], 1):
                doc = case.get("document", "")
                meta = case.get("metadata", {})
                cve_id = meta.get("cve_id", case.get("id", "N/A"))
                parts.append(f"\nCase {i} [{cve_id}]:\n{doc[:500]}")
            retrieved_section = "\n".join(parts)
        else:
            retrieved_section = "【Similar Historical Vulnerability Cases】\nNo similar cases found."

        # Few-shot section
        few_shot_section = ""
        if few_shot_text:
            few_shot_section = f"【Few-shot Examples】\n{few_shot_text}"

        return cls.STAGE2_TEMPLATE.format(
            code=code,
            language=language,
            sink_type=slice_data.get("sink_type", "unknown"),
            sink_category=slice_data.get("sink_category", "unknown"),
            source_var=slice_data.get("source_var", "unknown"),
            source_type=slice_data.get("source_type", "unknown"),
            dataflow_path=slice_data.get("dataflow_path", "unknown"),
            sanitization_info=slice_data.get("sanitization_detail", "None detected"),
            risk_level=slice_data.get("risk_level", "unknown"),
            retrieved_section=retrieved_section,
            few_shot_section=few_shot_section,
        )

    @classmethod
    def build_stage3(
        cls,
        code: str,
        language: str,
        finding: dict,
    ) -> str:
        return cls.STAGE3_TEMPLATE.format(
            code=code,
            language=language,
            has_vulnerability=finding.get("has_vulnerability", False),
            vulnerability_type=finding.get("vulnerability_type", "UNKNOWN"),
            confidence=finding.get("confidence", 0.0),
            severity=finding.get("severity", "UNKNOWN"),
            description=finding.get("description", "")[:300],
        )

    # ------------------------------------------------------------------
    # Dynamic Few-shot builder
    # ------------------------------------------------------------------

    @classmethod
    def build_few_shot(
        cls,
        code: str,
        language: str,
        retrieved_cases: list[dict],
        max_examples: int = 2,
    ) -> str:
        """Build few-shot examples from retrieved cases, preferring same-language
        and same-vulnerability-type cases."""
        examples: list[str] = []

        for case in retrieved_cases:
            metadata = case.get("metadata", {})
            if metadata.get("language") != language:
                continue
            doc = case.get("document", "")
            cve = metadata.get("cve_id", case.get("id", "N/A"))
            cwe = metadata.get("cwe_id", "N/A")
            has_fix = metadata.get("has_fix", False)

            example = f"""Example [{cve} — {cwe}]:
{doc[:400]}"""
            if has_fix:
                example += "\n(This case includes a verified patch/fix.)"
            examples.append(example)

            if len(examples) >= max_examples:
                break

        return "\n---\n".join(examples) if examples else ""
