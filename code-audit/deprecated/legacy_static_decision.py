"""DEPRECATED: V1 and V2 static decision strategies.

Moved to deprecated/ on 2026-07-20.
Reason: factory always routes to V3Aggressive (all presets set 'no_sink' explicitly).
These two classes are never instantiated in production.

Kept for reference — the simpler logic may be useful for future presets.
"""


class V1Conservative:
    """V1 IRIS: no-sink → uncertain (never returns 'safe')."""

    def __init__(self, params: dict):
        pass

    def decide(self, slice_data: dict) -> str:
        has_sink = bool(slice_data.get("sink_type"))
        if not has_sink:
            return "uncertain"

        risk = slice_data.get("risk_level", "medium")
        sank = slice_data.get("sanitization_detail", "")
        df = slice_data.get("dataflow_path", "")
        if risk == "high" and not sank and df and "?" not in df:
            return "vuln"
        return "uncertain"


class V2Moderate:
    """V2 old multi-agent: no-sink → safe, otherwise same as V1."""

    def __init__(self, params: dict):
        pass

    def decide(self, slice_data: dict) -> str:
        has_sink = bool(slice_data.get("sink_type"))
        if not has_sink:
            return "safe"

        risk = slice_data.get("risk_level", "medium")
        sank = slice_data.get("sanitization_detail", "")
        df = slice_data.get("dataflow_path", "")
        if risk == "high" and not sank and df and "?" not in df:
            return "vuln"
        return "uncertain"
