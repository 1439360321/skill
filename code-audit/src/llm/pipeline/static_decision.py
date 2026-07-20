"""Pluggable static decision strategies."""
from __future__ import annotations


class V3Aggressive:
    """V3 huoma999 V7: sanitizer threshold, low-risk handling."""

    def __init__(self, params: dict):
        self.no_sink = params.get("no_sink", "safe")
        self.low_risk_sink = params.get("low_risk_sink", "safe")
        self.sanitizer_threshold = params.get("sanitizer_threshold", 0)
        self.dataflow_required = params.get("dataflow_required", True)

    def decide(self, slice_data: dict) -> str:
        has_sink = bool(slice_data.get("sink_type"))
        if not has_sink:
            return self.no_sink

        risk = slice_data.get("risk_level", "medium")
        sank = slice_data.get("sanitization_detail", "")
        df = slice_data.get("dataflow_path", "")

        # Strong vuln signal
        if risk == "high":
            if not sank and (not self.dataflow_required or (df and "?" not in df)):
                return "vuln"

        # Sanitizer threshold
        if self.sanitizer_threshold > 0 and sank:
            sanitizers = [s.strip() for s in sank.split(";") if s.strip()]
            if len(sanitizers) >= self.sanitizer_threshold:
                return "safe"

        # Low risk with sink
        if risk == "low" and has_sink:
            return self.low_risk_sink

        return "uncertain"


def create_static_decision(params: dict):
    """Factory: always returns V3Aggressive (only active strategy)."""
    return V3Aggressive(params)
