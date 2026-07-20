"""Post-processing: result validation and CWE mapping."""

from __future__ import annotations

from typing import Any


class ResultValidator:
    """Validate and filter LLM results."""

    def validate_results(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Apply validation rules to a list of results."""
        validated: list[dict[str, Any]] = []
        for r in results:
            r = self._validate_one(r)
            if r is not None:
                validated.append(r)
        return validated

    def _validate_one(self, result: dict[str, Any]) -> dict[str, Any] | None:
        """Validate a single result. Returns None if it should be discarded."""
        if not result.get("has_vulnerability"):
            return result  # keep safe findings for metrics

        confidence = result.get("confidence", 0)
        from src.config import Config

        threshold = Config().evaluation.get("confidence_threshold", 0.6)
        if confidence < threshold:
            result["has_vulnerability"] = False
            result["status"] = "FILTERED_LOW_CONFIDENCE"
        else:
            result["status"] = "CONFIRMED"

        return result
