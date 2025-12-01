from __future__ import annotations

import asyncio
import datetime as dt
import logging
from asyncio.subprocess import Process
from typing import Any, Dict, List, Optional

from acs_manager.config.store import ConfigStore
from acs_manager.container.client import ContainerClient

logger = logging.getLogger(__name__)


class ContainerManager:
    """Handle ACS container lifecycle, IP tracking, and SSH composition/maintenance."""

    def __init__(self, store: ConfigStore, container_client: Optional[ContainerClient] = None) -> None:
        self.store = store
        self.container_client = container_client or ContainerClient(store)
        self.state: Dict[str, Any] = {
            "container_ip": None,
            "last_restart": None,
            "last_seen": None,
            "tunnel_status": "stopped",
            "tunnel_last_exit": None,
            "container_status": None,
            "container_start_time": None,
        }
        self._tunnel_process: Optional[Process] = None
        self._proc_lock = asyncio.Lock()
        self._stop_requested = False

    async def handle_new_ip(self, ip: str) -> None:
        """Update state when the sniffer reports a fresh IP and restart tunnel."""
        self.state["container_ip"] = ip
        self.state["last_seen"] = dt.datetime.utcnow()
        logger.info("Container IP updated to %s", ip)
        await self.restart_tunnel()

    def update_container_status(self, status: Optional[str], start_time: Optional[str]) -> None:
        self.state["container_status"] = status
        self.state["container_start_time"] = start_time

    async def ensure_running(self) -> None:
        """
        Entry point to be called when the capture layer detects a shutdown.
        Insert ACS-specific API/browser automation here to restart the container.
        """
        await self.restart_container()

    async def restart_container(self) -> None:
        """Restart container via ACS restart API."""
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.error("未配置 container_name，无法重启。")
            return

        task = self.container_client.find_instance_by_name(name)
        if not task:
            logger.error("未找到容器 %s，无法重启。", name)
            return
        task_id = task.get("instanceServiceId") or task.get("id")
        if not task_id:
            logger.error("容器 %s 缺少 instanceServiceId，无法重启。", name)
            return

        logger.warning("尝试重启容器 %s (task id: %s)", name, task_id)
        resp = self.container_client.restart_task(task_id)
        if str(resp.get("code")) == "0":
            logger.info("重启请求成功: %s", resp)
            self.state["last_restart"] = dt.datetime.utcnow()
            # exit monitor loop after successful restart request
            self._stop_requested = True
        else:
            logger.error("重启请求失败: %s", resp)

    def _parse_start_time(self, value: Optional[str]) -> Optional[dt.datetime]:
        if not value:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return dt.datetime.strptime(value, fmt)
            except ValueError:
                continue
        return None

    async def monitor_container(self, *, pre_shutdown_minutes: int = 10, slow_interval: int = 300, fast_interval: int = 30) -> None:
        """
        Periodically check container status; restart if stopped near shutdown window.
        """
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        shutdown_hours = acs_cfg.get("shutdown_hours", 360)
        if not name:
            logger.warning("No container_name configured; monitor_container exiting.")
            return

        while not self._stop_requested:
            interval = slow_interval
            try:
                info = self.container_client.get_container_instance_info_by_name(name)
                if info:
                    status = info.get("status")
                    start_time_str = info.get("startTime") or info.get("createTime")
                    self.update_container_status(status, start_time_str)
                    ip = info.get("instanceIp")
                    if ip:
                        await self.handle_new_ip(ip)

                    start_dt = self._parse_start_time(start_time_str)
                    if start_dt:
                        next_shutdown = start_dt + dt.timedelta(hours=shutdown_hours)
                        threshold = next_shutdown - dt.timedelta(minutes=pre_shutdown_minutes)
                        now = dt.datetime.utcnow()
                        interval = fast_interval if now >= threshold else slow_interval
                    if status and status.lower() in {"terminated", "stopped", "stop", "failed"}:
                        logger.warning("Container %s status %s -> attempting restart", name, status)
                        await self.restart_container()
                        break
                else:
                    logger.warning("Container %s not found; will retry soon", name)
                    interval = fast_interval
            except Exception as exc:  # pragma: no cover - network/API errors
                logger.error("Monitor loop error: %s", exc)
                interval = fast_interval

            await asyncio.sleep(interval)

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

        target_ip = self.state.get("container_ip") or ssh_cfg.get("container_ip")
        if not target_ip:
            raise ValueError("容器 IP 未知，尚未捕获或配置。")

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
            logger.info("检测到密码登录标记，请确保自动化安全处理密码输入。")
        return cmd

    def build_tunnel_command(self) -> List[str]:
        """Return ssh command for a persistent tunnel with port forwarding."""
        base = self.build_ssh_command()
        return ["ssh", "-o", "ExitOnForwardFailure=yes", "-N"] + base[1:]

    async def start_tunnel(self) -> None:
        """Start the SSH tunnel process if not already running."""
        async with self._proc_lock:
            if self._tunnel_process and self._tunnel_process.returncode is None:
                return
            try:
                cmd = self.build_tunnel_command()
            except Exception as exc:
                logger.error("Cannot build tunnel command: %s", exc)
                self.state["tunnel_status"] = "error"
                return

            logger.info("Starting SSH tunnel: %s", " ".join(cmd))
            proc = await asyncio.create_subprocess_exec(*cmd)
            self._tunnel_process = proc
            self.state["tunnel_status"] = "running"

    async def stop_tunnel(self) -> None:
        """Stop the SSH tunnel process and ensure port cleanup."""
        async with self._proc_lock:
            proc = self._tunnel_process
            if not proc:
                return
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
            self.state["tunnel_last_exit"] = dt.datetime.utcnow()
            self.state["tunnel_status"] = "stopped"
            self._tunnel_process = None

    async def restart_tunnel(self) -> None:
        """Restart tunnel to refresh forwarding and clean up ports."""
        await self.stop_tunnel()
        await self.start_tunnel()

    async def maintain_tunnel(self) -> None:
        """Keep the SSH tunnel alive; restart on exit or errors."""
        while not self._stop_requested:
            await self.start_tunnel()
            proc = self._tunnel_process
            if proc is None:
                await asyncio.sleep(3)
                continue
            try:
                rc = await proc.wait()
                logger.warning("SSH tunnel exited with code %s; restarting soon.", rc)
            except Exception as exc:  # pragma: no cover - subprocess errors
                logger.error("SSH tunnel crashed: %s", exc)
            finally:
                await self.stop_tunnel()
            await asyncio.sleep(3)

    async def shutdown(self) -> None:
        """Signal loop to stop and clean up the tunnel."""
        self._stop_requested = True
        await self.stop_tunnel()

    def snapshot(self) -> Dict[str, Any]:
        """Return a shallow copy of current state for the web UI."""
        return dict(self.state)

    def _acs_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("acs", default={}, reload=reload)

    def _ssh_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("ssh", default={}, reload=reload)
