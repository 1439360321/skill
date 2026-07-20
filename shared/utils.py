"""Shared utilities — logging, file-system helpers, and a lightweight config
loader that works without the full route-specific config.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import yaml


# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------


def get_logger(name: str = "vulnrag") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        logger.addHandler(h)
    return logger


# ------------------------------------------------------------------
# Config (lightweight)
# ------------------------------------------------------------------


def load_yaml(path: str | Path) -> dict[str, Any]:
    """Load a YAML file and return the parsed dict."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {p}")
    with open(p, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ------------------------------------------------------------------
# Source-file discovery
# ------------------------------------------------------------------

EXTENSION_MAP = {
    "c": [".c", ".h"],
    "python": [".py"],
    "java": [".java"],
}


def find_source_files(
    root: str | Path,
    languages: list[str] | None = None,
) -> list[Path]:
    """Recursively find source files."""
    root = Path(root)
    extensions: set[str] = set()
    for lang in languages or list(EXTENSION_MAP):
        extensions.update(EXTENSION_MAP.get(lang, []))
    files: list[Path] = []
    for ext in extensions:
        files.extend(root.rglob(f"*{ext}"))
    return sorted(files)


def detect_language(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in (".c", ".h"):
        return "c"
    if suffix == ".py":
        return "python"
    if suffix == ".java":
        return "java"
    return None
