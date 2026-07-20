"""Abstract LLM client — routes can swap between Ollama / Claude API / GPT-4o
without touching business logic.

Usage (in either route):
    from shared.llm.ollama_client import OllamaClient
    client = OllamaClient()
    response = client.generate(prompt)

Both routes share these clients; each route has its own Prompt builder.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseLLMClient(ABC):
    """Interface that every LLM backend must implement."""

    @abstractmethod
    def check_health(self) -> bool:
        """Return True if the service is reachable and the model is loaded."""
        ...

    @abstractmethod
    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Return raw text completion for *prompt*."""
        ...

    @abstractmethod
    def generate_with_json(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict[str, Any] | None:
        """Convenience: parse JSON from the completion.  Returns None on failure."""
        ...
