"""Configuration loader with singleton pattern."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


class Config:
    """Singleton configuration manager that loads from config.yaml."""

    _instance: "Config | None" = None
    _data: dict[str, Any] = {}

    def __new__(cls, config_path: str | Path | None = None) -> "Config":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load(config_path)
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (useful for testing)."""
        cls._instance = None
        cls._data = {}

    def _load(self, config_path: str | Path | None = None) -> None:
        if config_path is None:
            candidates = [
                Path.cwd() / "config.yaml",
                Path(__file__).resolve().parent.parent / "config.yaml",
            ]
            for candidate in candidates:
                if candidate.exists():
                    config_path = candidate
                    break

        if config_path is None or not Path(config_path).exists():
            raise FileNotFoundError("config.yaml not found in any known location")

        with open(config_path, "r", encoding="utf-8") as fh:
            self._data = yaml.safe_load(fh) or {}

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        value: Any = self._data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value

    @property
    def ollama(self) -> dict[str, Any]:
        return self._data.get("ollama", {})

    @property
    def scanner(self) -> dict[str, Any]:
        return self._data.get("scanner", {})

    @property
    def evaluation(self) -> dict[str, Any]:
        return self._data.get("evaluation", {})

    @property
    def rag(self) -> dict[str, Any]:
        return self._data.get("rag", {})

    @property
    def cache(self) -> dict[str, Any]:
        return self._data.get("cache", {})

    @property
    def multistage(self) -> dict[str, Any]:
        return self._data.get("multistage", {})

    @property
    def raw(self) -> dict[str, Any]:
        return dict(self._data)

    def __repr__(self) -> str:
        return f"<Config keys={list(self._data.keys())}>"
