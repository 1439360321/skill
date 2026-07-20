"""Pipeline orchestrator — assembles and executes the modular pipeline."""
from __future__ import annotations

import hashlib
import json

from .static_decision import create_static_decision
from .code_window import create_code_window
from .llm_strategy import create_llm_strategy, _build_context
from .post_processor import create_post_processor

# Bump this when pipeline logic changes to invalidate stale caches
_PIPELINE_VERSION = "2.0"


def _make_cache_key(slice_data: dict, params: dict) -> str:
    """Build a deterministic cache key from slice identity and pipeline params.

    Includes _PIPELINE_VERSION so that logic changes automatically invalidate
    old cached results.
    """
    identity = json.dumps({
        "code": slice_data.get("code", "")[:200],
        "sink": slice_data.get("sink_type", ""),
        "language": slice_data.get("language", "c"),
    }, sort_keys=True)
    param_hash = hashlib.md5(
        (json.dumps(params, sort_keys=True) + _PIPELINE_VERSION).encode()
    ).hexdigest()
    code_hash = hashlib.md5(identity.encode()).hexdigest()
    return f"{code_hash}_{param_hash}"


def run_pipeline(slice_data: dict, client, params: dict) -> dict:
    """Run the full modular pipeline and return result dict with stage outputs.

    Args:
        slice_data: slice dict from CodeSlicer
        client: LLM client (OpenAIClient)
        params: dict of all pipeline knobs

    Returns:
        dict with final_verdict, final_method, final_confidence, plus per-stage debug info.
    """
    # --- Cache lookup ---
    cache_key = _make_cache_key(slice_data, params)
    try:
        from src.utils.cache import CacheManager
        cache = CacheManager()
        cached = cache.get(cache_key)
        if cached is not None:
            cached["_cache_hit"] = True
            return cached
    except Exception:
        cache = None

    result = dict(slice_data)

    # --- Layer 0: Static decision ---
    static_params = params.get("static_decision", {})
    static_strategy = create_static_decision(static_params)
    decision = static_strategy.decide(slice_data)
    result["_static_decision"] = decision

    if decision == "vuln":
        result["final_verdict"] = "vuln"
        result["final_method"] = "static_deterministic"
        result["final_confidence"] = 0.9
        return result
    elif decision == "safe":
        result["final_verdict"] = "safe"
        result["final_method"] = "static_deterministic"
        result["final_confidence"] = 0.9
        return result

    # --- Layer 1: Code window ---
    window_params = params.get("code_window", {})
    window_strategy = create_code_window(window_params)
    code_window = window_strategy.extract(slice_data)
    result["_code_window"] = code_window[:500] + ("..." if len(code_window) > 500 else "")

    # --- Layer 1: Structured context ---
    context = _build_context(slice_data)
    result["_context"] = context

    # --- Layer 1.5: Tool aggregation (tool_aware_chain mode only) ---
    llm_params = params.get("llm", {})
    if llm_params.get("mode") == "tool_aware_chain":
        try:
            from src.scanner.tool_aggregator import aggregate
            # Build enriched tool report that Agent1 consumes
            tool_report = aggregate(slice_data, slice_data.get("language", "c"))
            # Add metadata Agent1 needs
            tool_report["_code_len"] = len(slice_data.get("code", ""))
            tool_report["_func_name"] = slice_data.get("function_name", "?")
            tool_report["_sources"] = slice_data.get("source_var", "unknown")
            tool_report["_dataflow"] = slice_data.get("dataflow_path", "?")
            slice_data["_tool_report"] = tool_report
            result["_tool_report_summary"] = {
                "tools_run": tool_report["tools_run"],
                "consensus": tool_report["consensus"]["level"],
                "blind_spots": tool_report["blind_spots"],
                "finding_count": tool_report["finding_count"],
            }
        except Exception as e:
            result["_tool_report_error"] = str(e)

    # --- Layer 2-4: LLM strategy ---
    # Merge json_parser from pipeline level
    llm_params["json_parser"] = params.get("json_parser", {}).get("mode", "robust")
    llm_strategy = create_llm_strategy(client, llm_params)
    llm_result = llm_strategy.analyze(slice_data, context, code_window)
    result.update(llm_result)
    result["_llm_calls"] = llm_strategy.llm_calls

    # --- Post-processing ---
    post_params = params.get("post_process", {})
    post_processor = create_post_processor(client, post_params)
    result = post_processor.process(result, slice_data, post_params)

    # --- Cache write (only LLM-path results, not static-only) ---
    if cache is not None and result.get("final_method", "").startswith("llm"):
        try:
            cache.set(cache_key, dict(result))
        except Exception:
            pass

    return result


# =========================================================================
# Preset configs
# =========================================================================

PRESET_V1 = {
    "static_decision": {
        "no_sink": "uncertain",
        "low_risk_sink": "uncertain",
        "sanitizer_threshold": 0,
        "dataflow_required": True,
    },
    "code_window": {
        "mode": "iris",
        "simple_max_chars": 1500,
        "iris_window_lines": 5,
        "iris_max_chars": 3000,
        "iris_fallback_chars": 2000,
    },
    "llm": {
        "mode": "agent_chain",
        "agent1_enabled": True,
        "agent1_temperature": 0.0,
        "agent1_max_tokens": 2048,
        "agent1_cot": False,
        "agent1_rag": False,
        "agent2_enabled": True,
        "agent2_temperature": 0.1,
        "agent2_max_tokens": 1024,
        "agent2_bias": "flag_it",
        "agent3_enabled": False,
        "agent3_temperature": 0.1,
        "agent3_max_tokens": 512,
    },
    "post_process": {
        "enable_conflict_arbitration": False,
        "enable_confidence_calibration": True,
        "enable_quality_check": True,
    },
    "json_parser": {"mode": "robust"},
}

PRESET_V2 = {
    "static_decision": {
        "no_sink": "safe",
        "low_risk_sink": "uncertain",
        "sanitizer_threshold": 0,
        "dataflow_required": True,
    },
    "code_window": {
        "mode": "simple",
        "simple_max_chars": 1500,
    },
    "llm": {
        "mode": "multi_temp_voting",
        "agent1_enabled": True,
        "agent1_temperature": 0.0,
        "agent1_max_tokens": 2048,
        "agent2_enabled": True,
        "agent2_temperature": 0.1,
        "agent2_max_tokens": 2048,
        "agent2_bias": "flag_it",
        "voting_temperatures": [0.0, 0.3, 0.7],
        "voting_weights": {},
        "voting_consensus": 2,
        "agent3_enabled": False,
        "agent3_temperature": 0.1,
        "agent3_max_tokens": 512,
    },
    "post_process": {
        "enable_conflict_arbitration": False,
        "enable_confidence_calibration": True,
        "enable_quality_check": True,
    },
    "json_parser": {"mode": "simple"},
}

PRESET_V3 = {
    "static_decision": {
        "no_sink": "safe",
        "low_risk_sink": "safe",
        "sanitizer_threshold": 2,
        "dataflow_required": True,
    },
    "code_window": {
        "mode": "dynamic",
        "simple_max_chars": 3000,
        "dynamic_iris_lines": 5,
        "dynamic_medium_chars": 3000,
    },
    "llm": {
        "mode": "single_pass",
        "single_pass_temperature": 0.3,
        "single_pass_max_tokens": 2048,
    },
    "post_process": {
        "enable_conflict_arbitration": False,
        "enable_confidence_calibration": True,
        "enable_quality_check": True,
    },
    "json_parser": {"mode": "robust"},
}

PRESET_V4 = {
    "static_decision": {
        "no_sink": "uncertain",
        "low_risk_sink": "uncertain",
        "sanitizer_threshold": 0,  # 0 = never skip based on sanitizer count; let LLM judge
        "dataflow_required": False,
    },
    "code_window": {
        "mode": "dynamic",
        "simple_max_chars": 3000,
        "dynamic_iris_lines": 5,
        "dynamic_medium_chars": 3000,
    },
    "llm": {
        "mode": "tool_aware_chain",
        "agent1_enabled": True,
        "agent1_temperature": 0.0,
        "agent1_max_tokens": 1024,
        "agent2_enabled": True,
        "agent2_temperature": 0.1,
        "agent2_max_tokens": 1024,
        "agent2_bias": "confirm_it",
        "agent3_enabled": True,
        "agent3_temperature": 0.1,
        "agent3_max_tokens": 512,
        "enable_rag": True,
    },
    "post_process": {
        "enable_conflict_arbitration": True,
        "enable_confidence_calibration": True,
        "enable_quality_check": True,
    },
    "json_parser": {"mode": "robust"},
}


def get_params(preset: str = "v1", overrides: dict | None = None) -> dict:
    """Get pipeline params from preset name, with optional overrides.

    Args:
        preset: "v1" | "v2" | "v3"
        overrides: dict of param overrides merged on top

    Returns:
        full params dict
    """
    presets = {"v1": PRESET_V1, "v2": PRESET_V2, "v3": PRESET_V3, "v4": PRESET_V4}
    params = dict(presets.get(preset, PRESET_V1))

    if overrides:
        for section in overrides:
            if section in params and isinstance(params[section], dict):
                params[section] = {**params[section], **overrides[section]}
            else:
                params[section] = overrides[section]

    return params
