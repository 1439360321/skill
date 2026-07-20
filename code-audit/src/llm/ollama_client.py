"""Ollama REST API client — unchanged from original VulnRAG-Audit
with minor additions for configurable temperature / max_tokens per call."""

from __future__ import annotations

import requests

from src.config import Config
from src.utils.logger import setup_logger

logger = setup_logger()


class OllamaClient:
    """Client for the Ollama REST API."""

    def __init__(self) -> None:
        self.config = Config()
        self.host = self.config.ollama.get("host", "http://localhost:11434")
        self.model = self.config.ollama.get("model", "deepseek-coder-v2:16b")
        self.default_temperature = self.config.ollama.get("temperature", 0.1)
        self.default_max_tokens = self.config.ollama.get("max_tokens", 2048)
        self.timeout = self.config.ollama.get("timeout", 120)
        self.max_retries = self.config.ollama.get("max_retries", 3)

    def check_health(self) -> bool:
        """Check whether Ollama is reachable and the configured model exists."""
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = [m.get("name", "") for m in resp.json().get("models", [])]
                available = any(self.model in m or m in self.model for m in models)
                if not available:
                    logger.warning(
                        f"Model '{self.model}' not found in: {models[:10]}..."
                    )
                return available
            return False
        except requests.ConnectionError:
            logger.error(
                f"Cannot connect to Ollama at {self.host}. "
                "Start with: ollama serve"
            )
            return False
        except Exception as e:
            logger.error(f"Ollama health check failed: {e}")
            return False

    def generate(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Send a generation request. Override temperature/max_tokens per call."""
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
                data = resp.json()
                return data.get("response", "")
            except requests.Timeout:
                last_error = requests.Timeout(
                    f"Ollama timed out after {self.timeout}s"
                )
                logger.warning(
                    f"Ollama timeout (attempt {attempt}/{self.max_retries})"
                )
            except Exception as e:
                last_error = e
                logger.warning(
                    f"Ollama error (attempt {attempt}/{self.max_retries}): {e}"
                )

        raise last_error or RuntimeError("Ollama generation failed")
