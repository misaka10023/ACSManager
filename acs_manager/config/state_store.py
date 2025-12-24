# -*- coding: utf-8 -*-
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict

from acs_manager.config.loader import dump_settings, load_settings


class RuntimeStateStore:
    """Lightweight store for runtime-only state (not meant for user editing)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _read(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            return load_settings(self.path) or {}
        except Exception:
            return {}

    def _write(self, data: Dict[str, Any]) -> None:
        dump_settings(self.path, data)

    def read_container(self, container_id: str) -> Dict[str, Any]:
        with self._lock:
            data = self._read()
            containers = data.get("containers") or {}
            if not isinstance(containers, dict):
                return {}
            entry = containers.get(str(container_id), {}) or {}
            return dict(entry) if isinstance(entry, dict) else {}

    def update_container(self, container_id: str, changes: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            data = self._read()
            containers = data.get("containers")
            if not isinstance(containers, dict):
                containers = {}
            current = containers.get(str(container_id), {})
            if not isinstance(current, dict):
                current = {}
            merged = dict(current)
            merged.update(changes)
            containers[str(container_id)] = merged
            data["containers"] = containers
            self._write(data)
            return dict(merged)
