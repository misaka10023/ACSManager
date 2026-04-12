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

    def rename_container(self, old_container_id: str, new_container_id: str) -> None:
        with self._lock:
            if not old_container_id or not new_container_id or old_container_id == new_container_id:
                return
            data = self._read()
            containers = data.get("containers")
            if not isinstance(containers, dict):
                return
            current = containers.pop(str(old_container_id), None)
            if current is None:
                return
            containers[str(new_container_id)] = current
            data["containers"] = containers
            self._write(data)

    def delete_container(self, container_id: str) -> None:
        with self._lock:
            data = self._read()
            containers = data.get("containers")
            if not isinstance(containers, dict):
                return
            if str(container_id) in containers:
                containers.pop(str(container_id), None)
                data["containers"] = containers
                self._write(data)

    def read_task(self, container_id: str, task_id: str) -> Dict[str, Any]:
        container_state = self.read_container(container_id)
        tasks = container_state.get("tasks") or {}
        if not isinstance(tasks, dict):
            return {}
        entry = tasks.get(str(task_id), {}) or {}
        return dict(entry) if isinstance(entry, dict) else {}

    def update_task(self, container_id: str, task_id: str, changes: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            data = self._read()
            containers = data.get("containers")
            if not isinstance(containers, dict):
                containers = {}
            current_container = containers.get(str(container_id), {})
            if not isinstance(current_container, dict):
                current_container = {}
            tasks = current_container.get("tasks")
            if not isinstance(tasks, dict):
                tasks = {}
            current_task = tasks.get(str(task_id), {})
            if not isinstance(current_task, dict):
                current_task = {}
            merged = dict(current_task)
            merged.update(changes)
            tasks[str(task_id)] = merged
            current_container = dict(current_container)
            current_container["tasks"] = tasks
            containers[str(container_id)] = current_container
            data["containers"] = containers
            self._write(data)
            return dict(merged)
