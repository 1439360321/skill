"""OpenAI-compatible API client — supports GLM, DeepSeek API, OpenAI, etc.

Implements ``BaseLLMClient`` so routes can swap between Ollama (local)
and cloud APIs without changing business logic.

Supported providers (auto-configured from base_url):
  - ZhipuAI GLM:   https://open.bigmodel.cn/api/paas/v4
  - DeepSeek API:   https://api.deepseek.com/v1
  - OpenAI:         https://api.openai.com/v1
  - Custom:         any OpenAI-compatible endpoint

Usage:
    from shared.llm.openai_client import OpenAIClient
    client = OpenAIClient(
        api_key="your-key",
        base_url="https://open.bigmodel.cn/api/paas/v4",
        model="glm-4.6",
    )
    text = client.generate("Hello")
    data = client.generate_with_json("Return JSON: {...}")
"""

from __future__ import annotations

import json
import re
from typing import Any

import requests

from shared.llm.base_client import BaseLLMClient


class OpenAIClient(BaseLLMClient):
    """OpenAI-compatible chat completions client.

    Works with ZhipuAI GLM, DeepSeek API, OpenAI, and any other
    provider that exposes a ``/chat/completions`` endpoint.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://open.bigmodel.cn/api/paas/v4",
        model: str = "glm-4.6",
        default_temperature: float = 0.1,
        default_max_tokens: int = 2048,
        timeout: int = 120,
        max_retries: int = 3,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.default_temperature = default_temperature
        self.default_max_tokens = default_max_tokens
        self.timeout = timeout
        self.max_retries = max_retries
        self._chat_url = f"{self.base_url}/chat/completions"

    # ------------------------------------------------------------------
    # BaseLLMClient interface
    # ------------------------------------------------------------------

    def check_health(self) -> bool:
        """Check if the API key and endpoint are valid."""
        try:
            resp = requests.post(
                self._chat_url,
                headers=self._headers(),
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                },
                timeout=30,
            )
            return resp.status_code == 200
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
        """Send a chat completion request and return the raw text response."""
        messages: list[dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": (
                temperature if temperature is not None else self.default_temperature
            ),
            "max_tokens": max_tokens or self.default_max_tokens,
            "thinking": {"type": "disabled"},
        }

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.post(
                    self._chat_url,
                    headers=self._headers(),
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                choices = data.get("choices", [])
                if choices:
                    msg = choices[0].get("message", {})
                    content = msg.get("content", "")
                    return str(content)
                return ""
            except requests.HTTPError as e:
                last_error = e
                if e.response is not None and e.response.status_code == 429:
                    import time
                    time.sleep(min(2 ** attempt, 30))
                    continue
                raise
            except Exception as e:
                last_error = e

        raise last_error or RuntimeError("API generation failed")

    def generate_with_json(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict[str, Any] | None:
        """Generate and parse JSON from the response."""
        text = self.generate(
            prompt,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return _extract_json(text)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }


# ------------------------------------------------------------------
# JSON extraction (shared with Ollama client logic)
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


# ------------------------------------------------------------------
# Factory — pick the right client from config
# ------------------------------------------------------------------


def _load_dotenv() -> None:
    """Load .env file from project root into os.environ (no-op if already set)."""
    import os
    from pathlib import Path

    # Search upward from this file to find .env
    cur = Path(__file__).resolve().parent
    for _ in range(4):
        env_file = cur / ".env"
        if env_file.exists():
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip()
                    if k not in os.environ:  # don't override existing env vars
                        os.environ[k] = v
            return
        cur = cur.parent


def create_llm_client(config_dict: dict | None = None):
    """Factory: return OllamaClient or OpenAIClient based on config.

    API keys are read from environment variables.  The convention is to
    reference them in config.yaml as ``${VAR_NAME}`` and store the actual
    values in a ``.env`` file (which is git-ignored).

    .. code-block:: yaml

        llm:
          provider: "openai"
          api_key: "${GLM_API_KEY}"
          base_url: "https://open.bigmodel.cn/api/paas/v4"
          model: "glm-4.6"
    """
    import os

    _load_dotenv()

    cfg = config_dict or {}

    provider = cfg.get("provider", "ollama")

    if provider == "openai":
        from shared.llm.openai_client import OpenAIClient

        api_key = cfg.get("api_key", "")
        if api_key.startswith("${") and api_key.endswith("}"):
            env_var = api_key[2:-1]
            api_key = os.environ.get(env_var, "")
        if not api_key:
            raise ValueError(
                "OpenAI provider requires api_key. Set it in config.yaml or "
                "export it as an environment variable."
            )

        return OpenAIClient(
            api_key=api_key,
            base_url=cfg.get("base_url", "https://open.bigmodel.cn/api/paas/v4"),
            model=cfg.get("model", "glm-4.6"),
            default_temperature=cfg.get("temperature", 0.1),
            default_max_tokens=cfg.get("max_tokens", 2048),
            timeout=cfg.get("timeout", 120),
            max_retries=cfg.get("max_retries", 3),
        )
    else:
        from shared.llm.ollama_client import OllamaClient

        return OllamaClient(
            host=cfg.get("host", "http://localhost:11434"),
            model=cfg.get("model", "deepseek-r1:8b"),
            default_temperature=cfg.get("temperature", 0.1),
            default_max_tokens=cfg.get("max_tokens", 2048),
            timeout=cfg.get("timeout", 120),
            max_retries=cfg.get("max_retries", 3),
        )
