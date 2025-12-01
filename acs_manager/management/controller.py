from __future__ import annotations

import asyncio
import datetime as dt
import getpass
import logging
from asyncio.subprocess import Process
from typing import Any, Dict, List, Optional

import psutil

from acs_manager.config.store import ConfigStore
from acs_manager.container.client import ContainerClient

logger = logging.getLogger(__name__)


class ContainerManager:
    """处理 ACS 容器生命周期、IP 跟踪与 SSH 隧道维护。"""

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
        self._tunnel_started_once = False

    async def handle_new_ip(self, ip: str) -> None:
        """捕获到新 IP 时更新状态并重启隧道。"""
        self.state["container_ip"] = ip
        self.state["last_seen"] = dt.datetime.utcnow()
        logger.info("容器 IP 更新为 %s", ip)
        await self.restart_tunnel()

    def update_container_status(self, status: Optional[str], start_time: Optional[str]) -> None:
        self.state["container_status"] = status
        self.state["container_start_time"] = start_time

    def resolve_container_ip(self, *, force_login: bool = True) -> Optional[str]:
        """在 IP 不明时通过 API 自动获取。"""
        name = self._acs_cfg(reload=True).get("container_name")
        if not name:
            logger.warning("未配置 acs.container_name，无法自动获取 IP。")
            return None
        if force_login:
            try:
                self.container_client.login()
            except Exception as exc:  # pragma: no cover - 网络异常
                logger.error("自动登录以获取容器 IP 失败: %s", exc)
                return None
        try:
            info = self.container_client.get_container_instance_info_by_name(name)
        except Exception as exc:  # pragma: no cover - 网络异常
            logger.error("通过 API 获取容器 %s 信息失败: %s", name, exc)
            return None
        if info and info.get("instanceIp"):
            ip = info["instanceIp"]
            self.state["container_ip"] = ip
            self.state["last_seen"] = dt.datetime.utcnow()
            logger.info("通过 API 自动获取容器 IP: %s", ip)
            return ip
        logger.warning("无法通过 API 获取容器 %s 的 IP。", name)
        return None

    async def ensure_running(self) -> None:
        """捕获到关闭时调用，立即尝试重启。"""
        await self.restart_container()

    async def restart_container(self) -> None:
        """调用 ACS 重启接口。"""
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.error("未配置 acs.container_name，无法重启。")
            return

        try:
            task = self.container_client.find_instance_by_name(name)
        except Exception as exc:
            logger.error("查询容器 %s 失败，无法重启: %s", name, exc)
            return
        if not task:
            logger.error("未找到容器 %s，无法重启。", name)
            return
        task_id = task.get("instanceServiceId") or task.get("id")
        if not task_id:
            logger.error("容器 %s 缺少 instanceServiceId，无法重启。", name)
            return

        logger.warning("尝试重启容器 %s (task id: %s)", name, task_id)
        try:
            resp = self.container_client.restart_task(task_id)
        except Exception as exc:
            logger.error("调用重启接口失败: %s", exc)
            return
        if str(resp.get("code")) == "0":
            logger.info("重启请求成功: %s", resp)
            self.state["last_restart"] = dt.datetime.utcnow()
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
        周期检查容器状态；接近超时时缩短检查间隔，停止时立即重启。
        """
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.warning("未配置 acs.container_name，监控退出。")
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
                    if start_dt and info.get("timeoutLimit"):
                        try:
                            hours, minutes, seconds = info["timeoutLimit"].split(":")
                            delta = dt.timedelta(hours=int(hours), minutes=int(minutes), seconds=int(seconds))
                            next_shutdown = start_dt + delta
                            threshold = next_shutdown - dt.timedelta(minutes=pre_shutdown_minutes)
                            now = dt.datetime.utcnow()
                            interval = fast_interval if now >= threshold else slow_interval
                        except Exception:
                            interval = slow_interval

                    if status and status.lower() in {"terminated", "stopped", "stop", "failed"}:
                        logger.warning("容器 %s 状态为 %s，触发重启。", name, status)
                        await self.restart_container()
                        break
                else:
                    logger.warning("容器 %s 未找到，将快速重试。", name)
                    interval = fast_interval
            except Exception as exc:  # pragma: no cover - 网络/API 异常
                logger.error("监控循环异常: %s", exc)
                interval = fast_interval

            await asyncio.sleep(interval)

    def build_ssh_command(self, *, reload_config: bool = True) -> List[str]:
        """
        组装 ssh 命令：
        - direct：直连容器
        - jump：使用 -J 跳板
        - double：双层 ssh（外层到跳板，内层到容器）
        """
        ssh_cfg = self._ssh_cfg(reload=reload_config)
        acs_cfg = self._acs_cfg(reload=reload_config)

        target_ip = self.state.get("container_ip") or ssh_cfg.get("container_ip")
        if not target_ip:
            target_ip = self.resolve_container_ip()
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
            if not bastion_host:
                raise ValueError("double 模式需要 ssh.bastion_host 或 ssh.remote_server_ip。")
            outer: List[str] = ["ssh", "-T"]
            add_identity(outer)
            add_port(outer, ssh_port)
            outer.append(f"{bastion_user}@{bastion_host}")
            inner: List[str] = ["ssh", "-T", "-o", "ExitOnForwardFailure=yes", "-N"]
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
                    raise ValueError("jump 模式需要 ssh.bastion_host 或 ssh.remote_server_ip。")
                cmd.extend(["-J", f"{bastion_user}@{bastion_host}"])
            add_forwards(cmd)
            cmd.append(f"{target_user}@{target_ip}")

        if password_login and password:
            logger.info("检测到密码登录标记，请确保自动化安全处理密码输入。")
        return cmd

    def build_tunnel_command(self) -> List[str]:
        """生成带端口转发的 ssh 隧道命令。"""
        base = self.build_ssh_command()
        mode = (self._ssh_cfg(reload=False).get("mode") or "jump").lower()
        # double 模式需要在跳板机执行内层 ssh 命令，不能在外层加 -N
        if mode == "double":
            return base
        return ["ssh", "-o", "ExitOnForwardFailure=yes", "-N"] + base[1:]

    def _forward_ports(self, ssh_cfg: Dict[str, Any]) -> List[int]:
        """收集需要监听的本地端口。"""
        ports: List[int] = []
        forwards = ssh_cfg.get("forwards") or []
        for spec in forwards:
            local = spec.get("local")
            if local:
                ports.append(int(local))
        if not ports:
            local_open_port = ssh_cfg.get("local_open_port")
            if local_open_port:
                ports.append(int(local_open_port))
        return ports

    def _ports_available(self, ports: List[int]) -> bool:
        """尝试绑定端口以检查占用。"""
        import socket

        for p in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("127.0.0.1", p))
                except OSError:
                    logger.error("本地端口 %s 已被占用，尝试自动清理后重试。", p)
                    return False
        return True

    def _kill_ssh_on_ports(self, ports: List[int]) -> None:
        """强杀占用端口的当前用户 ssh 进程。"""
        current_user = getpass.getuser()
        targets: List[int] = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port in ports and conn.status == psutil.CONN_LISTEN:
                if conn.pid is None:
                    continue
                try:
                    proc = psutil.Process(conn.pid)
                    if "ssh" in proc.name().lower() and proc.username() == current_user:
                        targets.append(proc.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        for pid in targets:
            try:
                proc = psutil.Process(pid)
                logger.warning("强制结束占用端口的 ssh 进程 pid=%s", pid)
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except psutil.TimeoutExpired:
                    proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    async def _ensure_ports_free(self, ports: List[int], retries: int = 3, delay: float = 1.0) -> bool:
        """在隧道重连时，重试释放端口后再启动。"""
        for attempt in range(retries):
            if self._ports_available(ports):
                return True
            await self.stop_tunnel()
            self._kill_ssh_on_ports(ports)
            if attempt < retries - 1:
                await asyncio.sleep(delay)
        return self._ports_available(ports)

    async def start_tunnel(self) -> None:
        """启动 SSH 隧道（若未运行）。"""
        async with self._proc_lock:
            if self._tunnel_process and self._tunnel_process.returncode is None:
                return
            try:
                cmd = self.build_tunnel_command()
                ssh_cfg = self._ssh_cfg(reload=True)
                ports = self._forward_ports(ssh_cfg)
                if self._tunnel_started_once and ports:
                    if not await self._ensure_ports_free(ports):
                        self.state["tunnel_status"] = "error"
                        return
            except Exception as exc:
                logger.error("无法构建隧道命令: %s", exc)
                self.state["tunnel_status"] = "error"
                return

            logger.info("启动 SSH 隧道: %s", " ".join(cmd))
            proc = await asyncio.create_subprocess_exec(*cmd)
            self._tunnel_process = proc
            self.state["tunnel_status"] = "running"
            self._tunnel_started_once = True

    async def stop_tunnel(self) -> None:
        """停止隧道并清理状态。"""
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
        """重启隧道以刷新转发并清理端口。"""
        await self.stop_tunnel()
        await self.start_tunnel()

    async def maintain_tunnel(self) -> None:
        """保持隧道存活，异常退出后自动重启。"""
        while not self._stop_requested:
            await self.start_tunnel()
            proc = self._tunnel_process
            if proc is None:
                await asyncio.sleep(3)
                continue
            try:
                rc = await proc.wait()
                logger.warning("SSH 隧道退出码 %s；稍后重启。", rc)
            except Exception as exc:  # pragma: no cover - 子进程异常
                logger.error("SSH 隧道崩溃: %s", exc)
            finally:
                await self.stop_tunnel()
            await asyncio.sleep(3)

    async def shutdown(self) -> None:
        """通知循环退出并关闭隧道。"""
        self._stop_requested = True
        await self.stop_tunnel()

    def snapshot(self) -> Dict[str, Any]:
        """获取当前状态（供 Web UI 展示）。"""
        return dict(self.state)

    def _acs_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("acs", default={}, reload=reload)

    def _ssh_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("ssh", default={}, reload=reload)
