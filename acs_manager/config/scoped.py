# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Any, Dict, List, Optional

from acs_manager.config.loader import dump_settings, get_section, load_settings


class ContainerScopedStore:
    """
    A light wrapper around the main config file that exposes a single container's
    settings (`acs`, `ssh`, etc.) as if they were the root-level sections.
    """

    @staticmethod
    def _compact_container(container: Dict[str, Any], base_acs: Dict[str, Any]) -> Dict[str, Any]:
        """Keep only name, minimal acs (container_name/service_type), ssh, and restart strategy."""
        name = container.get("name") or container.get("id")
        c_acs = container.get("acs", {}) if isinstance(container.get("acs"), dict) else {}
        compact_acs: Dict[str, Any] = {
            "container_name": c_acs.get("container_name") or name or base_acs.get("container_name"),
            "service_type": c_acs.get("service_type") or "container",
        }
        ssh = container.get("ssh", {}) if isinstance(container.get("ssh"), dict) else {}
        restart_cfg = container.get("restart", {}) if isinstance(container.get("restart"), dict) else {}
        restart_clean: Dict[str, Any] = {}
        if restart_cfg.get("strategy"):
            restart_clean["strategy"] = restart_cfg.get("strategy")
        payload: Dict[str, Any] = {"name": name, "acs": compact_acs, "ssh": ssh}
        if restart_clean:
            payload["restart"] = restart_clean
        return payload

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

        base_acs_raw = root.get("acs", {}) if isinstance(root.get("acs"), dict) else {}
        base_acs = {k: v for k, v in base_acs_raw.items() if k not in ("container_name", "service_type")}
        container_acs = container.get("acs", {}) if isinstance(container.get("acs"), dict) else {}
        merged_acs = dict(base_acs)
        merged_acs.update(container_acs)

        merged = dict(container)
        merged["name"] = merged.get("name") or merged.get("id")
        merged["acs"] = merged_acs
        merged["ssh"] = container.get("ssh", {})
        restart_cfg = container.get("restart", {}) if isinstance(container.get("restart"), dict) else {}
        merged["restart"] = {
            "strategy": (restart_cfg.get("strategy") or "restart"),
        }
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
        base_acs = root.get("acs", {}) if isinstance(root.get("acs"), dict) else {}
        base_acs = {k: v for k, v in base_acs.items() if k not in ("container_name", "service_type")}

        change_acs = changes.get("acs") if isinstance(changes, dict) else None
        global_acs_delta: Dict[str, Any] = {}
        container_acs_delta: Dict[str, Any] = {}
        change_restart = changes.get("restart") if isinstance(changes, dict) else None
        if isinstance(change_acs, dict):
            for k, v in change_acs.items():
                if k in ("container_name", "service_type"):
                    container_acs_delta[k] = v
                else:
                    global_acs_delta[k] = v
        if global_acs_delta:
            base_acs = {**base_acs, **global_acs_delta}
        if change_acs is not None:
            changes = dict(changes)
            changes["acs"] = container_acs_delta

        new_containers: List[Dict[str, Any]] = []
        found = False
        for item in containers:
            cid = str(item.get("id") or item.get("name") or "")
            if cid == self.container_id:
                updated = dict(item)
                updated.update(changes)
                if change_restart is not None:
                    updated["restart"] = {"strategy": change_restart.get("strategy")} if isinstance(change_restart, dict) else {}
                compact = self._compact_container(updated, base_acs)
                new_containers.append(compact)
                found = True
            else:
                new_containers.append(self._compact_container(item, base_acs))
        if not found:
            updated = dict(changes)
            if "name" not in updated:
                updated["name"] = self.container_id
            compact = self._compact_container(updated, base_acs)
            new_containers.append(compact)
        root["acs"] = base_acs
        root["containers"] = new_containers
        self._write_root(root)
        return self.read(reload=False)

    def write(self, data: Dict[str, Any]) -> Dict[str, Any]:
        root = self._read_root(reload=False)
        containers: List[Dict[str, Any]] = root.get("containers") or []
        base_acs = root.get("acs", {}) if isinstance(root.get("acs"), dict) else {}
        base_acs = {k: v for k, v in base_acs.items() if k not in ("container_name", "service_type")}

        data = dict(data)
        acs_in = data.pop("acs", {}) if isinstance(data, dict) else {}
        global_acs_delta: Dict[str, Any] = {}
        container_acs_delta: Dict[str, Any] = {}
        restart_delta = data.get("restart") if isinstance(data, dict) else None
        if isinstance(acs_in, dict):
            for k, v in acs_in.items():
                if k in ("container_name", "service_type"):
                    container_acs_delta[k] = v
                else:
                    global_acs_delta[k] = v
        if global_acs_delta:
            base_acs = {**base_acs, **global_acs_delta}
        data["acs"] = container_acs_delta

        new_containers: List[Dict[str, Any]] = []
        replaced = False
        for item in containers:
            cid = str(item.get("id") or item.get("name") or "")
            if cid == self.container_id:
                new_data = dict(data)
                if "name" not in new_data:
                    new_data["name"] = self.container_id
                if restart_delta is not None:
                    new_data["restart"] = {"strategy": restart_delta.get("strategy")} if isinstance(restart_delta, dict) else {}
                new_containers.append(self._compact_container(new_data, base_acs))
                replaced = True
            else:
                new_containers.append(self._compact_container(item, base_acs))
        if not replaced:
            new_data = dict(data)
            if "name" not in new_data:
                new_data["name"] = self.container_id
            if restart_delta is not None:
                new_data["restart"] = {"strategy": restart_delta.get("strategy")} if isinstance(restart_delta, dict) else {}
            new_containers.append(self._compact_container(new_data, base_acs))
        root["acs"] = base_acs
        root["containers"] = new_containers
        self._write_root(root)
        return self.read(reload=False)

    def reload(self) -> Dict[str, Any]:
        self._cache = load_settings(self.path)
        return self.read(reload=False)

    def format(self) -> str:
        # Mimic ConfigStore API
        return self.path.split(".")[-1]
