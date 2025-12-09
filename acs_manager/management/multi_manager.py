# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from acs_manager.config.scoped import ContainerScopedStore
from acs_manager.config.store import ConfigStore
from acs_manager.management.controller import ContainerManager

logger = logging.getLogger(__name__)


class MultiContainerManager:
    """Orchestrates multiple ContainerManager instances."""

    def __init__(self, base_store: ConfigStore) -> None:
        self.base_store = base_store
        self.managers: Dict[str, ContainerManager] = {}
        self._tasks: List[asyncio.Task] = []

    def _normalize_root(self) -> None:
        """
        Normalize config so that global `acs` is shared and per-container `acs`
        only keeps overrides (e.g., container_name / service_type).
        Also removes legacy `id` in favor of `name` as unique key.
        """
        try:
            root = self.base_store.read(reload=True)
            containers = root.get("containers") or []
            base_acs = root.get("acs", {}) if isinstance(root.get("acs"), dict) else {}
            normalized: List[Dict[str, Any]] = []
            for idx, c in enumerate(containers):
                if not isinstance(c, dict):
                    continue
                name = c.get("name") or c.get("id") or f"c{idx+1}"
                if not name:
                    continue
                c_acs = c.get("acs", {}) if isinstance(c.get("acs"), dict) else {}
                acs_override: Dict[str, Any] = {}
                # keep container_name/service_type even if same as base
                for key, val in c_acs.items():
                    if key == "container_name" or key == "service_type":
                        acs_override[key] = val
                        continue
                    if base_acs.get(key) != val:
                        acs_override[key] = val
                normalized.append(
                    {
                        "name": name,
                        "acs": acs_override,
                        "ssh": c.get("ssh", {}),
                    }
                )
            root["containers"] = normalized
            self.base_store.write(root)
        except Exception as exc:
            logger.warning("Failed to normalize config: %s", exc)

    def load_profiles(self) -> List[Dict[str, Any]]:
        root = self.base_store.read(reload=True)
        containers = root.get("containers") or []
        if not containers:
            # Backward compatibility: synthesize a single profile from legacy acs/ssh
            containers = [
                {
                    "id": (root.get("acs", {}) or {}).get("container_name") or "default",
                    "name": (root.get("acs", {}) or {}).get("container_name") or "default",
                    "acs": root.get("acs", {}),
                    "ssh": root.get("ssh", {}),
                }
            ]
        profiles: List[Dict[str, Any]] = []
        for idx, c in enumerate(containers):
            cid = str(c.get("id") or c.get("name") or f"c{idx+1}")
            name = c.get("name") or cid
            c = dict(c)
            c["id"] = cid
            c["name"] = name
            profiles.append(c)
        return profiles

    def init_managers(self) -> None:
        self._normalize_root()
        profiles = self.load_profiles()
        root = self.base_store.read(reload=True)
        if not root.get("containers"):
            root["containers"] = profiles
            try:
                self.base_store.write(root)
            except Exception as exc:
                logger.warning("Failed to persist synthesized containers list: %s", exc)
        for profile in profiles:
            cid = profile["id"]
            if cid in self.managers:
                continue
            scoped_store = ContainerScopedStore(self.base_store.path, cid) if hasattr(self.base_store, "path") else None
            if scoped_store is None:
                raise ValueError("Base config store must expose path for scoped containers.")
            manager = ContainerManager(scoped_store, container_id=cid, display_name=profile.get("name"))
            self.managers[cid] = manager

    async def start_background_tasks(self) -> List[asyncio.Task]:
        """Start maintain/monitor loops for all managers."""
        self.init_managers()
        tasks: List[asyncio.Task] = []
        for manager in self.managers.values():
            acs_cfg = manager._acs_cfg(reload=True)  # type: ignore[attr-defined]
            if acs_cfg.get("container_name"):
                tasks.append(asyncio.create_task(manager.prepare_on_start()))
            tasks.append(asyncio.create_task(manager.maintain_tunnel()))
            if acs_cfg.get("container_name"):
                tasks.append(
                    asyncio.create_task(
                        manager.monitor_container(pre_shutdown_minutes=10, slow_interval=300, fast_interval=30)
                    )
                )
        self._tasks = tasks
        return tasks

    async def shutdown(self) -> None:
        for task in self._tasks:
            task.cancel()
        for manager in self.managers.values():
            try:
                await manager.shutdown()
            except Exception as exc:
                logger.warning("Error shutting down container %s: %s", manager.container_id, exc)

    def list_states(self) -> List[Dict[str, Any]]:
        return [m.snapshot() for m in self.managers.values()]

    def get_manager(self, container_id: str) -> Optional[ContainerManager]:
        return self.managers.get(container_id)

    async def restart_tunnel(self, container_id: str) -> None:
        manager = self.get_manager(container_id)
        if not manager:
            raise ValueError(f"Container {container_id} not found")
        await manager.restart_tunnel()

    async def start_tunnel(self, container_id: str) -> None:
        manager = self.get_manager(container_id)
        if not manager:
            raise ValueError(f"Container {container_id} not found")
        await manager.start_tunnel()

    async def stop_tunnel(self, container_id: str) -> None:
        manager = self.get_manager(container_id)
        if not manager:
            raise ValueError(f"Container {container_id} not found")
        await manager.stop_tunnel()

    def resolve_container_ip(self, container_id: str, *, force_login: bool = True) -> Optional[str]:
        manager = self.get_manager(container_id)
        if not manager:
            raise ValueError(f"Container {container_id} not found")
        return manager.resolve_container_ip(force_login=force_login)
