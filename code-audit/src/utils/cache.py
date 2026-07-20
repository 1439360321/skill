"""Disk cache for LLM results to avoid repeated inference."""

from __future__ import annotations

import hashlib
import json
import pickle
import time
from pathlib import Path
from typing import Any

from src.config import Config
from src.utils.logger import setup_logger

logger = setup_logger()


class CacheManager:
    """Simple file-based cache with TTL."""

    def __init__(self, cache_dir: str | None = None):
        config = Config()
        self.enabled = config.cache.get("enabled", True)
        self.ttl_seconds = config.cache.get("ttl_hours", 24) * 3600
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path(config.cache.get("cache_dir", "./data/cache"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _key_to_path(self, key: str) -> Path:
        hash_hex = hashlib.md5(key.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{hash_hex}.pkl"

    def get(self, key: str) -> Any | None:
        if not self.enabled:
            return None
        path = self._key_to_path(key)
        if not path.exists():
            return None
        # Check TTL
        age = time.time() - path.stat().st_mtime
        if age > self.ttl_seconds:
            path.unlink(missing_ok=True)
            return None
        try:
            with open(path, "rb") as fh:
                return pickle.load(fh)
        except Exception as e:
            logger.warning(f"Cache read failed for key {key[:40]}: {e}")
            path.unlink(missing_ok=True)
            return None

    def set(self, key: str, value: Any) -> None:
        if not self.enabled:
            return
        path = self._key_to_path(key)
        try:
            with open(path, "wb") as fh:
                pickle.dump(value, fh)
        except Exception as e:
            logger.warning(f"Cache write failed for key {key[:40]}: {e}")

    def clear(self) -> int:
        count = 0
        for p in self.cache_dir.glob("*.pkl"):
            p.unlink()
            count += 1
        logger.info(f"Cleared {count} cache entries")
        return count
