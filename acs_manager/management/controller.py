from __future__ import annotations

import datetime as dt
import logging
from typing import Any, Dict, List

from acs_manager.config.store import ConfigStore

logger = logging.getLogger(__name__)


class ContainerManager:
    """Handle ACS container lifecycle, IP tracking, and SSH composition."""

    def __init__(self, store: ConfigStore) -> None:
        self.store = store
        self.state: Dict[str, Any] = {
            "container_ip": None,
            "last_restart": None,
            "last_seen": None,
        }

    async def handle_new_ip(self, ip: str) -> None:
        """Update state when the sniffer reports a fresh IP."""
        self.state["container_ip"] = ip
        self.state["last_seen"] = dt.datetime.utcnow()
        logger.info("Container IP updated to %s", ip)

    async def ensure_running(self) -> None:
        """
        Entry point to be called when the capture layer detects a shutdown.
        Insert ACS-specific API/browser automation here to restart the container.
        """
        await self.restart_container()

    async def restart_container(self) -> None:
        """Placeholder for ACS restart logic (web automation or API call)."""
        acs_cfg = self._acs_cfg(reload=True)
        logger.warning(
            "Restart logic not implemented for container `%s`. Implement ACS restart workflow here.",
            acs_cfg.get("container_name", "<unknown>"),
        )
        self.state["last_restart"] = dt.datetime.utcnow()

    def build_ssh_command(self, *, reload_config: bool = True) -> List[str]:
        """Compose the ssh command (supports jump host and port forwarding)."""
        target_ip = self.state.get("container_ip")
        if not target_ip:
            raise ValueError("Container IP is unknown. Capture layer has not reported it.")

        ssh_cfg = self._ssh_cfg(reload=reload_config)
        target_user = ssh_cfg.get("target_user", "root")
        bastion_host = ssh_cfg.get("bastion_host")
        bastion_user = ssh_cfg.get("bastion_user") or target_user
        identity_file = ssh_cfg.get("identity_file")
        forwards = ssh_cfg.get("forwards", [])

        cmd: List[str] = ["ssh"]
        if identity_file:
            cmd.extend(["-i", identity_file])
        if bastion_host:
            cmd.extend(["-J", f"{bastion_user}@{bastion_host}"])
        for spec in forwards:
            local = spec.get("local")
            remote = spec.get("remote")
            if local and remote:
                cmd.extend(["-L", f"{local}:localhost:{remote}"])

        cmd.append(f"{target_user}@{target_ip}")
        return cmd

    def snapshot(self) -> Dict[str, Any]:
        """Return a shallow copy of current state for the web UI."""
        return dict(self.state)

    def _acs_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("acs", default={}, reload=reload)

    def _ssh_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("ssh", default={}, reload=reload)
