"""LLM-First hybrid detector — config-driven modular pipeline.

All pipeline stages are pluggable via pipeline/orchestrator.py.
Config presets: v1 (IRIS) | v2 (multi-temp) | v3 (single-pass).

Compatibility: static_decision(), extract_structured_context(), agent1_screen()
are kept as module-level wrappers for eval_one.py backward compat.
"""
from __future__ import annotations

import json
import re
from typing import Any

from src.utils.logger import setup_logger

logger = setup_logger()

# Re-export pipeline functions for eval_one.py compatibility
from src.llm.pipeline.llm_strategy import (
    parse_json, agent1_screen as _agent1_screen,
)
from src.llm.pipeline.orchestrator import (
    run_pipeline, get_params,
)
from src.llm.pipeline.llm_strategy import _build_context


# =========================================================================
# Compatibility wrappers for eval_one.py
# =========================================================================

def static_decision(slice_data: dict) -> str:
    """Compatibility wrapper. Uses pipeline's configured static decision strategy."""
    from src.config import Config
    cfg = Config()._data.get("pipeline", {})
    preset = cfg.get("preset", "v1")
    overrides = cfg.get("overrides", {})
    params = get_params(preset, overrides if overrides else None)
    from src.llm.pipeline.static_decision import create_static_decision
    strategy = create_static_decision(params.get("static_decision", {}))
    return strategy.decide(slice_data)


def extract_structured_context(slice_data: dict) -> dict:
    """Compatibility wrapper. Uses unified context builder."""
    return _build_context(slice_data)


def agent1_screen(client, context: dict) -> dict | None:
    """Compatibility wrapper. Uses pipeline's configured agent1."""
    from src.config import Config
    cfg = Config()._data.get("pipeline", {})
    preset = cfg.get("preset", "v1")
    overrides = cfg.get("overrides", {})
    params = get_params(preset, overrides if overrides else None)
    llm_params = params.get("llm", {})
    llm_params["json_parser"] = params.get("json_parser", {}).get("mode", "robust")
    return _agent1_screen(client, context, llm_params)


def _parse_json(text: str) -> dict | None:
    """Legacy compatibility — delegates to robust parser."""
    return parse_json(text, mode="robust")


# =========================================================================
# Main detector
# =========================================================================

class LLMFirstDetector:
    """Config-driven pipeline orchestrator.

    Reads pipeline.preset from config.yaml to select strategy.
    """

    def __init__(self, preset: str | None = None, overrides: dict | None = None):
        from src.config import Config
        from shared.llm.openai_client import create_llm_client
        Config.reset()
        cfg = Config()
        pipeline_cfg = cfg._data.get("pipeline", {})
        llm_config = cfg._data.get("llm", cfg._data.get("ollama", {}))

        self.client = create_llm_client(llm_config)
        self.llm_calls = 0

        # Resolve params
        self.preset = preset or pipeline_cfg.get("preset", "v1")
        _overrides = overrides or pipeline_cfg.get("overrides", {})
        self.params = get_params(self.preset, _overrides if _overrides else None)

    def detect(self, slice_data: dict) -> dict:
        """Run the full modular pipeline on one slice."""
        result = run_pipeline(slice_data, self.client, self.params)
        self.llm_calls += result.get("_llm_calls", 0)

        # Clean up internal debug keys for public result
        for key in list(result.keys()):
            if key.startswith("_") and key != "_sample_id":
                pass  # keep for now, Streamlit needs them

        return result
