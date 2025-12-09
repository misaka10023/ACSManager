# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Any, Dict, List, Optional

from acs_manager.config.loader import dump_settings, get_section, load_settings


class ContainerScopedStore:
    """
    A light wrapper around the main config file that exposes a single container's
    settings (`acs`, `ssh`, etc.) as if they were the root-level sections.
    """

    def __init__(self, path: str, container_id: str) -> None:
        self.path = path
        self.container_id = str(container_id)
        self._cache: Optional[Dict[str, Any]] = None

    def _read_root(self, reload: bool = False) -> Dict[str, Any]:
        if reload or self._cache is None:
            self._cache = load_settings(self.path)
        return dict(self._cache or {})

    def _find_container(self, root: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        containers: List[Dict[str, Any]] = root.get("containers") or []
        for item in containers:
            cid = str(item.get("id") or item.get("name") or "")
            if cid == self.container_id:
                return item
        return None

    def read(self, *, reload: bool = False) -> Dict[str, Any]:
        root = self._read_root(reload=reload)
        container = self._find_container(root)
        if container is None:
            raise ValueError(f"Container {self.container_id} not found in config")

        base_acs = root.get("acs", {}) if isinstance(root.get("acs"), dict) else {}
        container_acs = container.get("acs", {}) if isinstance(container.get("acs"), dict) else {}
        merged_acs = dict(base_acs)
        merged_acs.update(container_acs)

        merged = dict(container)
        merged["acs"] = merged_acs
        merged["ssh"] = container.get("ssh", {})
        return merged

    def get_section(
        self,
        key: str,
        default: Dict[str, Any] | None = None,
        *,
        reload: bool = False,
    ) -> Dict[str, Any]:
        return get_section(self.read(reload=reload), key, default)

    def _write_root(self, root: Dict[str, Any]) -> None:
        dump_settings(self.path, root)
        # refresh cache
        self._cache = dict(root)

    def update(self, changes: Dict[str, Any]) -> Dict[str, Any]:
        root = self._read_root(reload=False)
        containers: List[Dict[str, Any]] = root.get("containers") or []
        new_containers: List[Dict[str, Any]] = []
        found = False
        for item in containers:
            cid = str(item.get("id") or item.get("name") or "")
            if cid == self.container_id:
                updated = dict(item)
                updated.update(changes)
                if "id" not in updated:
                    updated["id"] = self.container_id
                new_containers.append(updated)
                found = True
            else:
                new_containers.append(item)
        if not found:
            updated = dict(changes)
            updated["id"] = self.container_id
            new_containers.append(updated)
        root["containers"] = new_containers
        self._write_root(root)
        return self.read(reload=False)

    def write(self, data: Dict[str, Any]) -> Dict[str, Any]:
        root = self._read_root(reload=False)
        containers: List[Dict[str, Any]] = root.get("containers") or []
        new_containers: List[Dict[str, Any]] = []
        replaced = False
        for item in containers:
            cid = str(item.get("id") or item.get("name") or "")
            if cid == self.container_id:
                new_data = dict(data)
                if "id" not in new_data:
                    new_data["id"] = self.container_id
                new_containers.append(new_data)
                replaced = True
            else:
                new_containers.append(item)
        if not replaced:
            new_data = dict(data)
            if "id" not in new_data:
                new_data["id"] = self.container_id
            new_containers.append(new_data)
        root["containers"] = new_containers
        self._write_root(root)
        return self.read(reload=False)

    def reload(self) -> Dict[str, Any]:
        self._cache = load_settings(self.path)
        return self.read(reload=False)

    def format(self) -> str:
        # Mimic ConfigStore API
        return self.path.split(".")[-1]
