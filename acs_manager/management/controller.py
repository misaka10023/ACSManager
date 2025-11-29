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
        """
        Compose the ssh command.

        Supports three modes via config:
        - direct: simple ssh to the container.
        - jump: use ProxyJump (-J).
        - double: two-hop ssh (ssh bastion ... ssh container ...).
        """
        ssh_cfg = self._ssh_cfg(reload=reload_config)
        acs_cfg = self._acs_cfg(reload=reload_config)

        target_ip = (
            self.state.get("container_ip")
            or ssh_cfg.get("container_ip")
            or acs_cfg.get("container_ip_hint")
        )
        if not target_ip:
            raise ValueError("Container IP is unknown. Capture layer has not reported it.")

        mode = (ssh_cfg.get("mode") or "jump").lower()
        target_user = ssh_cfg.get("target_user", "root")
        bastion_host = ssh_cfg.get("bastion_host") or ssh_cfg.get("remote_server_ip")
        bastion_user = ssh_cfg.get("bastion_user") or target_user
        identity_file = ssh_cfg.get("identity_file")
        ssh_port = ssh_cfg.get("port")
        password_login = ssh_cfg.get("password_login")
        password = ssh_cfg.get("password")
        forwards = ssh_cfg.get("forwards", [])
        local_open_port = ssh_cfg.get("local_open_port")
        container_open_port = ssh_cfg.get("container_open_port")

        def add_forwards(base: List[str]) -> None:
            for spec in forwards:
                local = spec.get("local")
                remote = spec.get("remote")
                if local and remote:
                    base.extend(["-L", f"{local}:localhost:{remote}"])
            if not forwards and local_open_port and container_open_port:
                base.extend(["-L", f"{local_open_port}:localhost:{container_open_port}"])

        def add_identity(base: List[str]) -> None:
            if identity_file:
                base.extend(["-i", identity_file])

        def add_port(base: List[str], port_value: Any) -> None:
            if port_value:
                base.extend(["-p", str(port_value)])

        if mode == "double":
            # ssh to bastion, then ssh from bastion to container
            if not bastion_host:
                raise ValueError("double mode requires ssh.bastion_host or ssh.remote_server_ip")
            outer: List[str] = ["ssh"]
            add_identity(outer)
            add_port(outer, ssh_port)
            outer.append(f"{bastion_user}@{bastion_host}")
            inner: List[str] = ["ssh"]
            add_port(inner, ssh_cfg.get("container_port") or ssh_port)
            add_identity(inner)
            add_forwards(inner)
            inner.append(f"{target_user}@{target_ip}")
            outer.append(" ".join(inner))
            cmd = outer
        else:
            cmd: List[str] = ["ssh"]
            add_port(cmd, ssh_port)
            add_identity(cmd)
            if mode == "jump":
                if not bastion_host:
                    raise ValueError("jump mode requires ssh.bastion_host or ssh.remote_server_ip")
                cmd.extend(["-J", f"{bastion_user}@{bastion_host}"])
            add_forwards(cmd)
            cmd.append(f"{target_user}@{target_ip}")

        if password_login and password:
            logger.info("Password login requested; ensure automation handles password entry securely.")
        return cmd

    def snapshot(self) -> Dict[str, Any]:
        """Return a shallow copy of current state for the web UI."""
        return dict(self.state)

    def _acs_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("acs", default={}, reload=reload)

    def _ssh_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("ssh", default={}, reload=reload)
