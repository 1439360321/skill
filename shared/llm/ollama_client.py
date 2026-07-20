"""Shared Ollama client — used by both route-1 (API security) and
route-2 (code audit).  Identical interface to the original; factored out
so either route can run without importing the other's modules.
"""

from __future__ import annotations

import json
import re
from typing import Any

import requests

from shared.llm.base_client import BaseLLMClient


class OllamaClient(BaseLLMClient):
    """Ollama REST API client — shared across all routes."""

    def __init__(
        self,
        host: str = "http://localhost:11434",
        model: str = "deepseek-r1:8b",
        default_temperature: float = 0.1,
        default_max_tokens: int = 2048,
        timeout: int = 120,
        max_retries: int = 3,
    ) -> None:
        self.host = host
        self.model = model
        self.default_temperature = default_temperature
        self.default_max_tokens = default_max_tokens
        self.timeout = timeout
        self.max_retries = max_retries

    # ------------------------------------------------------------------
    # BaseLLMClient interface
    # ------------------------------------------------------------------

    def check_health(self) -> bool:
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = [m.get("name", "") for m in resp.json().get("models", [])]
                return any(self.model in m or m in self.model for m in models)
            return False
        except Exception:
            return False

    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": (
                    temperature
                    if temperature is not None
                    else self.default_temperature
                ),
                "num_predict": max_tokens or self.default_max_tokens,
            },
        }
        if system:
            payload["system"] = system

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.post(
                    f"{self.host}/api/generate",
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return resp.json().get("response", "")
            except Exception as e:
                last_error = e

        raise last_error or RuntimeError("Ollama generation failed")

    def generate_with_json(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict[str, Any] | None:
        text = self.generate(
            prompt,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return _extract_json(text)


# ------------------------------------------------------------------
# JSON extraction (used by both routes)
# ------------------------------------------------------------------


def _extract_json(text: str) -> dict[str, Any] | None:
    """Extract a JSON dict from LLM output."""
    if not text or not text.strip():
        return None
    # Markdown code block
    for m in re.finditer(r"```(?:json)?\s*([\s\S]*?)\s*```", text):
        try:
            return json.loads(m.group(1).strip())
        except json.JSONDecodeError:
            continue
    # Raw JSON
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass
    # Brace-delimited block
    brace = re.search(r"\{[\s\S]*\}", text)
    if brace:
        try:
            return json.loads(brace.group())
        except json.JSONDecodeError:
            pass
    return None
