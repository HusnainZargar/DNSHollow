"""Settings read/write with validation and a short cache.
The dashboard and API use this; nothing reads a config file."""
from __future__ import annotations

import copy
import threading
import time

from .db import Database
from .engine.scorer import validate_settings
from .engine.settings import DEFAULTS, deep_update, merge_settings


class SettingsError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class SettingsStore:
    TTL = 5.0   # seconds; settings changes apply within this time

    def __init__(self, db: Database):
        self.db = db
        self._cache: dict | None = None
        self._at = 0.0
        self._lock = threading.Lock()

    def get(self) -> dict:
        """Full merged settings (a copy: safe to modify)."""
        with self._lock:
            if self._cache is None or time.time() - self._at > self.TTL:
                self._cache = merge_settings(self.db.load_settings())
                self._at = time.time()
            return copy.deepcopy(self._cache)

    def _save(self, cfg: dict) -> dict:
        errors = validate_settings(cfg)
        if errors:
            raise SettingsError(errors)
        merged = merge_settings(cfg)
        self.db.save_settings(merged)
        with self._lock:
            self._cache = merged
            self._at = time.time()
        return copy.deepcopy(merged)

    def replace(self, cfg: dict) -> dict:
        """Full config. Missing keys fall back to defaults."""
        return self._save(cfg)

    def patch(self, partial: dict) -> dict:
        """Change only the keys given; keep everything else."""
        return self._save(deep_update(self.get(), partial))

    def reset(self) -> dict:
        self.db.delete_settings()
        with self._lock:
            self._cache = copy.deepcopy(DEFAULTS)
            self._at = time.time()
        return copy.deepcopy(DEFAULTS)
