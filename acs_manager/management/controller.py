from __future__ import annotations

import datetime as dt
import logging
from typing import Any, Dict, List, Optional

from acs_manager.config.loader import get_section

logger = logging.getLogger(__name__)


class ContainerManager:
    """Handle ACS container lifecycle and connectivity."""

    def __init__(self, settings: Dict[str, Any]) -> None:
        self.settings = settings
        self.acs_cfg = get_section(settings, "acs")
        self.ssh_cfg = get_section(settings, "ssh")
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
        logger.warning(
            "Restart logic not implemented. Implement ACS restart workflow here."
        )
        self.state["last_restart"] = dt.datetime.utcnow()

    def build_ssh_command(self) -> List[str]:
        """Compose the ssh command (supports jump host and port forwarding)."""
        target_ip = self.state.get("container_ip")
        if not target_ip:
            raise ValueError("Container IP is unknown. Capture layer has not reported it.")

        target_user = self.ssh_cfg.get("target_user", "root")
        bastion_host = self.ssh_cfg.get("bastion_host")
        bastion_user = self.ssh_cfg.get("bastion_user") or target_user
        identity_file = self.ssh_cfg.get("identity_file")
        forwards = self.ssh_cfg.get("forwards", [])

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
