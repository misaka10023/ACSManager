from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict

from acs_manager.config.loader import dump_settings, get_section, load_settings


class ConfigStore:
    """
    Thread-safe config cache with reload/read/update helpers.
    Allows the running app and Web UI to read and persist the latest settings.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._cache: Dict[str, Any] = {}
        self._format = self.path.suffix.lower()
        self.reload()

    def reload(self) -> Dict[str, Any]:
        """Force reload from disk and refresh the cache."""
        with self._lock:
            self._cache = load_settings(self.path)
            return dict(self._cache)

    def read(self, *, reload: bool = False) -> Dict[str, Any]:
        """Return the cached config, optionally reloading from disk first."""
        with self._lock:
            if reload or not self._cache:
                self._cache = load_settings(self.path)
            return dict(self._cache)

    def get_section(
        self,
        key: str,
        default: Dict[str, Any] | None = None,
        *,
        reload: bool = False,
    ) -> Dict[str, Any]:
        """Convenience to fetch a mapping section with validation."""
        return get_section(self.read(reload=reload), key, default)

    def write(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace the entire config and persist to disk."""
        with self._lock:
            self._cache = dict(data)
            dump_settings(self.path, self._cache)
            return dict(self._cache)

    def update(self, changes: Dict[str, Any]) -> Dict[str, Any]:
        """Shallow-merge changes into the config and persist."""
        with self._lock:
            merged = dict(self._cache)
            merged.update(changes)
            self._cache = merged
            dump_settings(self.path, self._cache)
            return dict(self._cache)

    def format(self) -> str:
        return self._format
