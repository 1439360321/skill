"""Pluggable post-processing strategies for the 3-agent architecture.

  ConflictArbitrator          — Agent2 vs Agent3 disagreement → LLM tiebreaker
  ConfidenceCalibrator        — Adjust confidence by agreement/evidence quality
  OutputQualityChecker        — Flag suspicious outputs (empty reasoning, etc.)
"""

from __future__ import annotations

from src.utils.logger import setup_logger

logger = setup_logger()


class NoOpPostProcessor:
    def process(self, result: dict, slice_data: dict, params: dict) -> dict:
        return result


# =========================================================================
# LLM-driven post-processors
# =========================================================================

ARBITRATOR_PROMPT = """You are a vulnerability analysis arbiter. Two agents reviewed the same function with different scopes and reached different conclusions. Do NOT re-analyze the code. Only judge whose reasoning is more valid.

Agent2 (focused window review):
  Scope: code around tool-identified sink functions
  Judgment: {a2_verdict}
  Confidence: {a2_confidence}
  Reasoning: {a2_reasoning}

Agent3 (full function review):
  Scope: entire function, especially code outside Agent2's window
  Judgment: {a3_verdict}
  Confidence: {a3_confidence}
  Reasoning: {a3_reasoning}

Rules:
1. If Agent3 found a concrete issue outside Agent2's window → Agent3 is correct (Agent2 couldn't see it)
2. If Agent3's reasoning is vague ("might", "could be") and Agent2 is specific → Agent2 is correct
3. If both have valid points (Agent2 is right about its area, Agent3 is right about another) → both can be right, final=vuln
4. Default: prefer the agent with higher confidence AND more specific reasoning

Return raw JSON (no markdown):
{{"winner": "agent2"|"agent3"|"both", "final_verdict": "vuln"|"safe", "confidence": 0.0-1.0, "reasoning": "one sentence why"}}"""


class ConflictArbitrator:
    """Resolve Agent2 vs Agent3 disagreements via lightweight LLM call.

    Only triggered when A2 and A3 disagree on final_verdict.
    Does NOT re-analyze code — only reads the two agents' reasoning.
    """

    def __init__(self, client, params: dict):
        self.client = client
        self.temperature = params.get("arbitrator_temperature", 0.0)
        self.max_tokens = params.get("arbitrator_max_tokens", 256)

    def process(self, result: dict, slice_data: dict, params: dict) -> dict:
        a2 = result.get("_agent2_raw", {})
        a3 = result.get("_agent3_raw", {})

        # Only trigger if both agents ran and disagree
        if not a2 or not a3:
            return result

        a2_vuln = self._to_bool(a2)
        a3_vuln = self._to_bool(a3)

        if a2_vuln == a3_vuln:
            return result  # no conflict

        logger.info(
            f"Conflict detected: A2={'vuln' if a2_vuln else 'safe'} "
            f"vs A3={'vuln' if a3_vuln else 'safe'}"
        )

        prompt = ARBITRATOR_PROMPT.format(
            a2_verdict="vuln" if a2_vuln else "safe",
            a2_confidence=a2.get("confidence", "unknown"),
            a2_reasoning=a2.get("reasoning", a2.get("llm_reasoning", "none")),
            a3_verdict="vuln" if a3_vuln else "safe",
            a3_confidence=a3.get("confidence", "unknown"),
            a3_reasoning=a3.get("reasoning", a3.get("llm_reasoning", "none")),
        )

        try:
            from src.llm.pipeline.llm_strategy import parse_json
            resp = self.client.generate(prompt, temperature=self.temperature,
                                        max_tokens=self.max_tokens)
            arb = parse_json(resp, mode="simple")
            if arb:
                result["final_verdict"] = arb.get("final_verdict", result["final_verdict"])
                result["final_confidence"] = arb.get("confidence", result["final_confidence"])
                result["final_method"] = result.get("final_method", "") + "_arbitrated"
                result["llm_reasoning"] = (result.get("llm_reasoning", "") +
                                           f" [ARBITRATOR: {arb.get('reasoning', '')}]")
                result["_arbitrator_raw"] = arb
                logger.info(f"Arbitrator: winner={arb.get('winner')}, verdict={arb.get('final_verdict')}")
        except Exception as e:
            logger.warning(f"Arbitrator failed: {e}")

        return result

    @staticmethod
    def _to_bool(agent_result: dict) -> bool | None:
        v = agent_result.get("verdict", "")
        if v in ("vulnerable", "confirmed_vuln", "vuln"):
            return True
        if v in ("safe", "false_positive"):
            return False
        if agent_result.get("has_vulnerability") is True:
            return True
        if agent_result.get("has_vulnerability") is False:
            return False
        return None


class ConfidenceCalibrator:
    """Adjust confidence based on cross-agent agreement and evidence quality.

    Zero LLM cost — purely rule-based.

    Agent3 is a BLIND-SPOT SCANNER only — it does NOT judge safety.
      - A3 finds vuln → overturn A2's safe (threshold ≥0.8)
      - A3 finds nothing (None) → no adjustment (A2 stands)
      - A3 not triggered (A2=vuln, high conf) → no penalty
    """

    A3_OVERTURN_THRESHOLD = 0.7      # blind-spot finding: A2 couldn't see this area
    A3_OVERLAP_THRESHOLD  = 0.85     # overlapping finding: contradicting A2's review

    def process(self, result: dict, slice_data: dict, params: dict) -> dict:
        fc = result.get("final_confidence", 0.5)
        fv = result.get("final_verdict", "")

        a2 = result.get("_agent2_raw", {})
        a3 = result.get("_agent3_raw", {})

        # ================================================================
        # Agent3 blind-spot calibration (differentiated thresholds)
        # ================================================================
        if a3:
            a3_has_vuln = a3.get("has_vulnerability", False)
            a3_conf = float(a3.get("confidence", 0.5))
            is_independent = self._different_finding(a2, a3)

            if a3_has_vuln and fv == "vuln":
                # A3 found the blind-spot vuln that caused the overturn
                if is_independent:
                    # Blind spot discovery — lower threshold, higher boost
                    if a3_conf < self.A3_OVERTURN_THRESHOLD:
                        # Finding too weak, revert to A2's original verdict
                        result["final_verdict"] = "safe"
                        fc = max(fc - 0.05, 0.3)
                        result["_calibration_note"] = "A3_blind_spot_weak_reverted"
                    else:
                        fc = min(fc + 0.1, 0.98)
                        result["_calibration_note"] = "A3_blind_spot_independent"
                else:
                    # Overlapping — A3 re-evaluated A2's area, needs stronger evidence
                    if a3_conf < self.A3_OVERLAP_THRESHOLD:
                        result["final_verdict"] = "safe"
                        fc = max(fc - 0.1, 0.25)
                        result["_calibration_note"] = "A3_overlap_weak_reverted"
                    else:
                        fc = a3_conf
                        result["_calibration_note"] = "A3_overlap_strong_accepted"

            elif a3_has_vuln and fv == "safe":
                # A3 found something but it didn't reach overturn threshold in _run_a3
                fc = max(fc - 0.05, 0.35)
                result["_calibration_note"] = "A3_finding_weak_no_overturn"

        elif not a3 and fv == "vuln":
            # A3 was not triggered (A2=vuln, high confidence)
            if a2:
                result["_calibration_note"] = "A3_skipped_A2_confident"

        # A3 returned None (no findings) → no adjustment, A2's verdict stands as-is

        # ================================================================
        # Reasoning quality check
        # ================================================================
        reasoning = result.get("llm_reasoning", "")
        if reasoning:
            vague = any(w in reasoning.lower()
                       for w in ["might", "could be", "possibly", "may be"])
            if vague and "concrete" not in reasoning.lower():
                fc = max(fc - 0.1, 0.25)
                result.setdefault("_calibration_note", result.get("_calibration_note", "") + "_vague")
            if len(reasoning) < 20:
                fc = max(fc - 0.15, 0.2)
                result.setdefault("_calibration_note", result.get("_calibration_note", "") + "_short")

        # ================================================================
        # Tool consensus bonus (only for vuln verdicts with strong static signal)
        # ================================================================
        sd = slice_data
        patterns = sd.get("code_patterns", [])
        if patterns and len(patterns) >= 2 and fv == "vuln":
            fc = min(fc + 0.05, 0.95)
            result.setdefault("_calibration_note", result.get("_calibration_note", "") + "_tool_consensus")

        result["final_confidence"] = round(fc, 4)
        return result

    @staticmethod
    def _different_finding(a2: dict, a3: dict) -> bool:
        """Check if A3 found a different vulnerability than A2 (independent confirm)."""
        a2_reason = (a2.get("reasoning") or a2.get("llm_reasoning") or "").lower()
        a3_reason = (a3.get("reasoning") or a3.get("llm_reasoning") or "").lower()

        # Different CWE or different area mentioned
        a2_cwe = a2.get("cwe_type", a2.get("cwe_id", ""))
        a3_cwe = a3.get("cwe_type", a3.get("cwe_id", ""))

        if a2_cwe and a3_cwe and a2_cwe != a3_cwe:
            return True

        # A3 mentions "outside", "additional", "blind spot", "elsewhere"
        blind_spot_words = ["outside", "additional", "blind", "elsewhere",
                           "further", "another", "also found"]
        if any(w in a3_reason for w in blind_spot_words) and a3_reason != a2_reason[:50]:
            return True

        return False


class OutputQualityChecker:
    """Flag suspicious outputs: empty reasoning, overconfident, inconsistent.

    Zero LLM cost — purely rule-based.
    """

    def process(self, result: dict, slice_data: dict, params: dict) -> dict:
        warnings = result.setdefault("_quality_warnings", [])

        # Empty reasoning on vuln verdict
        if result.get("final_verdict") == "vuln":
            reasoning = result.get("llm_reasoning", "")
            if not reasoning or len(reasoning) < 10:
                warnings.append("vuln_verdict_without_reasoning")
                result["final_confidence"] = min(result.get("final_confidence", 0.5), 0.4)

        # Overconfident (>0.95) without strong evidence
        fc = result.get("final_confidence", 0.5)
        if fc > 0.95:
            reasoning = result.get("llm_reasoning", "")
            if len(reasoning) < 50:
                warnings.append("overconfident_short_reasoning")
                result["final_confidence"] = 0.85

        # Agent saw nothing but still judged vuln
        a2 = result.get("_agent2_raw", {})
        if (result.get("final_verdict") == "vuln"
                and a2.get("verdict") == "false_positive"
                and not result.get("_agent3_raw")):
            warnings.append("vuln_despite_a2_safe_no_a3")

        return result


# =========================================================================
# Chained processor
# =========================================================================

class ChainedPostProcessor:
    def __init__(self, processors: list):
        self.processors = processors

    def process(self, result: dict, slice_data: dict, params: dict) -> dict:
        for p in self.processors:
            result = p.process(result, slice_data, params)
        return result


# =========================================================================
# Factory
# =========================================================================

def create_post_processor(client, params: dict):
    """Factory: return post-processor chain based on params."""
    processors = []

    if params.get("enable_conflict_arbitration") and client:
        processors.append(ConflictArbitrator(client, params))
    if params.get("enable_confidence_calibration", True):
        processors.append(ConfidenceCalibrator())
    if params.get("enable_quality_check", True):
        processors.append(OutputQualityChecker())

    if not processors:
        return NoOpPostProcessor()
    if len(processors) == 1:
        return processors[0]
    return ChainedPostProcessor(processors)
