# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from acs_manager.config.state_store import RuntimeStateStore
from acs_manager.config.scoped import ContainerScopedStore
from acs_manager.config.store import ConfigStore
from acs_manager.management.controller import ContainerManager

logger = logging.getLogger(__name__)


class MultiContainerManager:
    """Orchestrates multiple ContainerManager instances."""

    def __init__(self, base_store: ConfigStore) -> None:
        self.base_store = base_store
        self.state_store = RuntimeStateStore(self._derive_state_path())
        self.managers: Dict[str, ContainerManager] = {}
        self._tasks_by_manager: Dict[str, List[asyncio.Task]] = {}

    def _derive_state_path(self) -> Path:
        cfg_path = Path(self.base_store.path)
        root_dir = cfg_path.parent
        if root_dir.name.lower() in {"local", "dev", "prod"} and root_dir.parent.exists():
            root_dir = root_dir.parent
        state_dir = root_dir / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        return state_dir / "runtime_state.yaml"

    def normalize_root(self) -> None:
        """
        Normalize config:
        - Global `acs` is shared.
        - Each container keeps only `acs.container_name` (drops legacy id and service_type).
        - Migrate ssh.remote_server_ip -> ssh.bastion_host.
        """
        try:
            root = self.base_store.read(reload=True)
            containers = root.get("containers") or []
            base_acs = root.get("acs", {}) if isinstance(root.get("acs"), dict) else {}
            root["acs"] = base_acs
            normalized: List[Dict[str, Any]] = []
            for idx, c in enumerate(containers):
                if not isinstance(c, dict):
                    continue
                name = c.get("name") or c.get("id") or f"c{idx+1}"
                if not name:
                    continue
                c_acs_raw = c.get("acs", {}) if isinstance(c.get("acs"), dict) else {}
                container_name = c_acs_raw.get("container_name") or name
                acs_override: Dict[str, Any] = {
                    "container_name": container_name,
                }
                ssh_raw = c.get("ssh", {}) if isinstance(c.get("ssh"), dict) else {}
                ssh_clean = dict(ssh_raw)
                if not ssh_clean.get("bastion_host") and ssh_clean.get("remote_server_ip"):
                    ssh_clean["bastion_host"] = ssh_clean.get("remote_server_ip")
                ssh_clean.pop("remote_server_ip", None)
                restart_cfg = c.get("restart", {}) if isinstance(c.get("restart"), dict) else {}
                restart_clean = {}
                if isinstance(restart_cfg, dict) and restart_cfg.get("strategy"):
                    restart_clean["strategy"] = restart_cfg.get("strategy")
                normalized.append(
                    {
                        "name": name,
                        "acs": acs_override,
                        "ssh": ssh_clean,
                        "restart": restart_clean,
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
                    "name": (root.get("acs", {}) or {}).get("container_name") or "default",
                    "acs": root.get("acs", {}),
                    "ssh": root.get("ssh", {}),
                }
            ]
        profiles: List[Dict[str, Any]] = []
        for idx, c in enumerate(containers):
            cid = str(c.get("name") or c.get("id") or f"c{idx+1}")
            name = c.get("name") or cid
            c = dict(c)
            c["id"] = cid  # internal id kept for manager key
            c["name"] = name
            profiles.append(c)
        return profiles

    def init_managers(self) -> None:
        self.normalize_root()
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
            manager.bind_state_store(self.state_store)

    def _should_start_tasks(self, manager: ContainerManager, *, log: bool = False) -> bool:
        name = manager.configured_container_name(reload=True)
        if not name:
            if log:
                logger.info(
                    "Container %s has placeholder name; background tasks disabled.",
                    manager.container_id,
                )
            return False
        return True

    @staticmethod
    def _has_active_tasks(tasks: List[asyncio.Task]) -> bool:
        return any(not task.done() for task in tasks)

    async def _stop_tasks_for(self, manager: ContainerManager, tasks: List[asyncio.Task]) -> None:
        if not tasks:
            return
        for task in tasks:
            task.cancel()
        try:
            await manager.stop_tunnel()
        except Exception as exc:
            logger.warning("Failed to stop tunnel for %s: %s", manager.container_id, exc)

    def _spawn_tasks_for(self, manager: ContainerManager) -> List[asyncio.Task]:
        tasks: List[asyncio.Task] = []
        if not self._should_start_tasks(manager, log=True):
            return tasks
        tasks.append(asyncio.create_task(manager.prepare_on_start()))
        tasks.append(asyncio.create_task(manager.maintain_tunnel()))
        tasks.append(
            asyncio.create_task(
                manager.monitor_container(pre_shutdown_minutes=10, slow_interval=300, fast_interval=30)
            )
        )
        return tasks

    async def sync_managers(self) -> None:
        """
        Sync in-memory managers with current config containers.
        Removed containers are shut down and pruned; new containers are started.
        """
        profiles = self.load_profiles()
        desired: Dict[str, Dict[str, Any]] = {p["id"]: p for p in profiles}

        for cid in list(self.managers.keys()):
            if cid not in desired:
                manager = self.managers.pop(cid)
                tasks = self._tasks_by_manager.pop(cid, [])
                await self._stop_tasks_for(manager, tasks)
                try:
                    await manager.shutdown()
                except Exception as exc:
                    logger.warning("Error shutting down container %s: %s", cid, exc)

        for profile in profiles:
            cid = profile["id"]
            name = profile.get("name") or cid
            if cid in self.managers:
                manager = self.managers[cid]
                if name and manager.display_name != name:
                    manager.display_name = name
                    manager.state["name"] = name
                tasks = self._tasks_by_manager.get(cid, [])
                should_run = self._should_start_tasks(manager)
                if should_run and not self._has_active_tasks(tasks):
                    logger.info("Starting background tasks for container %s after config update.", cid)
                    self._tasks_by_manager[cid] = self._spawn_tasks_for(manager)
                elif not should_run and tasks:
                    logger.info("Stopping background tasks for container %s (placeholder name).", cid)
                    await self._stop_tasks_for(manager, tasks)
                    self._tasks_by_manager[cid] = []
                continue
            scoped_store = ContainerScopedStore(self.base_store.path, cid) if hasattr(self.base_store, "path") else None
            if scoped_store is None:
                raise ValueError("Base config store must expose path for scoped containers.")
            manager = ContainerManager(scoped_store, container_id=cid, display_name=name)
            self.managers[cid] = manager
            manager.bind_state_store(self.state_store)
            self._tasks_by_manager[cid] = self._spawn_tasks_for(manager)

    async def start_background_tasks(self) -> List[asyncio.Task]:
        """Start maintain/monitor loops for all managers."""
        self.init_managers()
        tasks: List[asyncio.Task] = []
        for manager in self.managers.values():
            manager_tasks = self._spawn_tasks_for(manager)
            self._tasks_by_manager[manager.container_id] = manager_tasks
            tasks.extend(manager_tasks)
        return tasks

    async def shutdown(self) -> None:
        for task_list in self._tasks_by_manager.values():
            for task in task_list:
                task.cancel()
        for manager in self.managers.values():
            try:
                await manager.shutdown()
            except Exception as exc:
                logger.warning("Error shutting down container %s: %s", manager.container_id, exc)
        self._tasks_by_manager.clear()

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

    async def restart_container(self, container_id: str) -> None:
        manager = self.get_manager(container_id)
        if not manager:
            raise ValueError(f"Container {container_id} not found")
        await manager.restart_container()

    def resolve_container_ip(self, container_id: str, *, force_login: bool = True) -> Optional[str]:
        manager = self.get_manager(container_id)
        if not manager:
            raise ValueError(f"Container {container_id} not found")
        return manager.resolve_container_ip(force_login=force_login)
