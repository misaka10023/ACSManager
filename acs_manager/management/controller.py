# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import datetime as dt
import getpass
import logging
import os
import subprocess
from asyncio.subprocess import Process
from typing import Any, Dict, List, Optional

import psutil

from acs_manager.config.store import ConfigStore
from acs_manager.container.client import ContainerClient
from acs_manager.config.state_store import RuntimeStateStore

logger = logging.getLogger(__name__)


class ContainerManager:
    """处理 ACS 容器生命周期、IP 跟踪与 SSH 隧道维护。"""

    def __init__(
        self,
        store: ConfigStore,
        container_client: Optional[ContainerClient] = None,
        *,
        container_id: str = "default",
        display_name: Optional[str] = None,
        state_store: Optional[RuntimeStateStore] = None,
    ) -> None:
        self.store = store
        self.container_id = container_id
        self.display_name = display_name or container_id
        self.container_client = container_client or ContainerClient(store)
        self.state_store = state_store
        self.state: Dict[str, Any] = {
            "id": self.container_id,
            "name": self.display_name,
            "container_ip": None,
            "next_shutdown": None,
            "remaining_seconds": None,
            "timeout_limit": None,
            "last_restart": None,
            "last_seen": None,
            "tunnel_status": "stopped",
            "tunnel_last_exit": None,
            "container_status": None,
            "container_start_time": None,
            "remaining_time_str": None,
        }
        self._tunnel_process: Optional[Process] = None
        self._proc_lock = asyncio.Lock()
        self._stop_requested = False
        self._tunnel_started_once = False
        self._tunnel_failure_count = 0

    async def handle_new_ip(self, ip: str) -> None:
        """捕获到新的容器 IP 时更新状态，若隧道已启动则重启隧道。"""
        old_ip = self.state.get("container_ip")
        self.state["last_seen"] = dt.datetime.now()

        if old_ip == ip and self._tunnel_started_once:
            logger.debug("Container IP unchanged (%s); heartbeat only.", ip)
            return

        self.state["container_ip"] = ip
        # Persist latest IP to config for this container (ssh.container_ip)
        try:
            ssh_cfg = self._ssh_cfg(reload=False)
            if isinstance(ssh_cfg, dict):
                updated_ssh = dict(ssh_cfg)
                updated_ssh["container_ip"] = ip
                self.store.update({"ssh": updated_ssh})
        except Exception as exc:
            logger.warning("Failed to persist container_ip to config: %s", exc)

        if not self._tunnel_started_once:
            logger.info("Captured container IP for the first time: %s; waiting for tunnel init.", ip)
            return

        logger.info("Container IP updated to %s (old %s); restarting tunnel.", ip, old_ip)
        await self.restart_tunnel()

    def update_container_status(self, status: Optional[str], start_time: Optional[str]) -> None:
        """更新容器状态与启动时间。"""
        self.state["container_status"] = status
        self.state["container_start_time"] = start_time

    def resolve_container_ip(self, *, force_login: bool = True) -> Optional[str]:
        """在 IP 未知时通过 API 自动获取。"""
        name = self._acs_cfg(reload=True).get("container_name")
        if not name:
            logger.warning("acs.container_name not configured; cannot auto-resolve IP.")
            return None
        ssh_cfg = self._ssh_cfg(reload=False)
        if force_login:
            try:
                self.container_client.login()
            except Exception as exc:  # pragma: no cover - network errors
                logger.error("Login failed while resolving container IP: %s", exc)
                return None
        try:
            info = self.container_client.get_container_instance_info_by_name(name)
        except Exception as exc:  # pragma: no cover - network errors
            logger.error("Failed to query container %s via API: %s", name, exc)
            return None
        if info and info.get("instanceIp"):
            ip = info["instanceIp"]
            self.state["container_ip"] = ip
            self.state["last_seen"] = dt.datetime.now()
            logger.info("Resolved container IP via API: %s", ip)
            return ip
        logger.warning("Could not resolve container %s IP from API.", name)
        return None
    async def ensure_running(self) -> None:
        """检测到容器停止时触发重启。"""
        await self.restart_container()

    def _recreate_container_task(self, base_name: str, task: Dict[str, Any]) -> bool:
        """创建新的任务实例，名称遵循 baseName_counter_timestamp。"""
        task_id = task.get("instanceServiceId") or task.get("id")
        if not task_id:
            logger.error("Cannot recreate task without instanceServiceId/id.")
            return False

        restart_cfg = self._restart_cfg(reload=False)
        new_count = restart_cfg.get("create_count", 0) + 1
        timestamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
        new_name = f"{base_name}_{new_count}_{timestamp}"

        try:
            detail = self.container_client.get_instance_detail(task_id)
        except Exception as exc:
            logger.error("Failed to fetch task detail for recreate: %s", exc)
            return False

        data = detail.get("data") if isinstance(detail, dict) else None
        if data is None and isinstance(detail, dict):
            data = detail
        if not isinstance(data, dict):
            logger.error("Unexpected detail format when recreating task %s", task_id)
            return False

        payload: Dict[str, Any] = {}
        allowed_keys = [
            "description",
            "taskType",
            "acceleratorType",
            "version",
            "imagePath",
            "timeoutLimit",
            "taskNumber",
            "resourceGroup",
            "useStartScript",
            "startScriptActionScope",
            "startScriptContent",
            "cpuNumber",
            "ramSize",
            "gpuNumber",
            "env",
            "mountInfoList",
            "containerPortInfoList",
            "headerNotebookId",
            "headerNotebookIp",
        ]
        for key in allowed_keys:
            if key in data and data[key] is not None:
                payload[key] = data[key]

        payload["instanceServiceName"] = new_name
        payload.setdefault("description", data.get("description", ""))
        payload.setdefault("taskType", (data.get("taskType") or "jupyter"))
        payload.setdefault("acceleratorType", data.get("acceleratorType") or "gpu")
        payload.setdefault("timeoutLimit", data.get("timeoutLimit") or "360:00:00")
        payload.setdefault("taskNumber", data.get("taskNumber") or 1)
        payload.setdefault("resourceGroup", data.get("resourceGroup") or "default")
        payload.setdefault("useStartScript", data.get("useStartScript") or False)
        payload.setdefault("startScriptActionScope", data.get("startScriptActionScope") or "all")
        payload.setdefault("startScriptContent", data.get("startScriptContent") or "")
        payload.setdefault("cpuNumber", data.get("cpuNumber") or 1)
        payload.setdefault("ramSize", data.get("ramSize") or 1024)
        payload.setdefault("gpuNumber", data.get("gpuNumber") or 0)
        payload.setdefault("env", data.get("env") or "")
        payload.setdefault("mountInfoList", data.get("mountInfoList") or [])
        payload.setdefault("containerPortInfoList", data.get("containerPortInfoList") or [])

        try:
            resp = self.container_client.create_task(payload)
        except Exception as exc:
            logger.error("Create new task failed: %s", exc)
            return False

        if str(resp.get("code")) == "0":
            restart_cfg.update(
                {
                    "strategy": restart_cfg.get("strategy") or "recreate",
                    "create_count": new_count,
                    "last_created_at": dt.datetime.now().isoformat(),
                    "last_created_name": new_name,
                }
            )
            self._persist_restart_cfg(restart_cfg)
            self.state["last_restart"] = dt.datetime.now()
            logger.info("Created new task %s from %s: %s", new_name, base_name, resp)
            try:
                # Persist the new ACS container name so后续 IP 解析/隧道重启使用新任务
                self.store.update({"acs": {"container_name": new_name}})
            except Exception as exc:  # pragma: no cover - IO errors
                logger.warning("Failed to persist new container_name %s: %s", new_name, exc)
            return True

        logger.error("Create new task failed: %s", resp)
        return False

    async def restart_container(self) -> None:
        """调用 ACS 重启接口。"""
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.error("acs.container_name not configured; cannot restart.")
            return

        try:
            task = self.container_client.find_instance_by_name(name)
        except Exception as exc:
            logger.error("Failed to query container %s; cannot restart: %s", name, exc)
            return
        if not task:
            logger.error("Container %s not found; cannot restart.", name)
            return
        task_id = task.get("instanceServiceId") or task.get("id")
        if not task_id:
            logger.error("Container %s missing instanceServiceId; cannot restart.", name)
            return

        restart_cfg = self._restart_cfg(reload=True)
        if restart_cfg.get("strategy") == "recreate":
            base_name = self.display_name or name
            logger.warning("Recreate strategy enabled; creating new task for %s (base name: %s)", name, base_name)
            created = self._recreate_container_task(base_name, task)
            if created:
                return
            logger.warning("Recreate task failed; falling back to restart original task.")

        logger.warning("Attempting to restart container %s (task id: %s)", name, task_id)
        try:
            resp = self.container_client.restart_task(task_id)
        except Exception as exc:
            logger.error("Restart API call failed: %s", exc)
            return
        if str(resp.get("code")) == "0":
            logger.info("Restart request accepted: %s", resp)
            self.state["last_restart"] = dt.datetime.now()
        else:
            logger.error("Restart request failed: %s", resp)

    def _parse_start_time(self, value: Optional[str]) -> Optional[dt.datetime]:
        """解析时间字符串为 datetime。"""
        if not value:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return dt.datetime.strptime(value, fmt)
            except ValueError:
                continue
        return None

    def _parse_remaining_time_str(self, value: Optional[str]) -> Optional[int]:
        """解析 ACS remainingTime 文本，如 "14d 23h 48m"，返回秒数。"""
        if not value:
            return None
        text = str(value).strip()
        if not text:
            return None
        total = 0
        for part in text.split():
            part = part.strip()
            try:
                if part.endswith("d"):
                    total += int(part[:-1]) * 24 * 3600
                elif part.endswith("h"):
                    total += int(part[:-1]) * 3600
                elif part.endswith("m"):
                    total += int(part[:-1]) * 60
            except ValueError:
                continue
        return total or None

    async def monitor_container(self, *, pre_shutdown_minutes: int = 10, slow_interval: int = 300, fast_interval: int = 30) -> None:
        """周期检查容器状态，接近超时时加快轮询，停止则重启。"""
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.warning("acs.container_name not configured; monitor loop exits.")
            return

        while not self._stop_requested:
            interval = slow_interval
            try:
                try:
                    info = self.container_client.get_container_instance_info_by_name(name)
                except Exception as exc:
                    # 认证失败尝试重新登录一次
                    try:
                        if hasattr(exc, "response") and getattr(exc.response, "status_code", None) == 401:  # type: ignore[attr-defined]
                            self.container_client.login()
                            info = self.container_client.get_container_instance_info_by_name(name)
                        else:
                            raise
                    except Exception:
                        raise
                if info:
                    status = info.get("status")
                    start_time_str = info.get("startTime") or info.get("createTime")
                    self.update_container_status(status, start_time_str)
                    ip = info.get("instanceIp")
                    if ip:
                        await self.handle_new_ip(ip)

                    # 使用 startTime + timeoutLimit 计算预计停止时间与剩余秒数
                    start_dt = self._parse_start_time(start_time_str)
                    timeout_str = info.get("timeoutLimit")
                    now = dt.datetime.now()
                    if start_dt and timeout_str:
                        try:
                            self.state["timeout_limit"] = timeout_str
                            hours, minutes, seconds = timeout_str.split(":")
                            delta = dt.timedelta(hours=int(hours), minutes=int(minutes), seconds=int(seconds))
                            next_shutdown = start_dt + delta
                            self.state["next_shutdown"] = next_shutdown.strftime("%Y-%m-%d %H:%M:%S")
                            remaining = (next_shutdown - now).total_seconds()
                            remaining_sec = int(remaining) if remaining > 0 else 0
                            self.state["remaining_seconds"] = remaining_sec
                            if remaining_sec > 0:
                                days = remaining_sec // 86400
                                hours_left = (remaining_sec % 86400) // 3600
                                mins_left = (remaining_sec % 3600) // 60
                                parts = []
                                if days > 0:
                                    parts.append(f"{days}d")
                                if hours_left > 0:
                                    parts.append(f"{hours_left}h")
                                if mins_left > 0 or not parts:
                                    parts.append(f"{mins_left}m")
                                self.state["remaining_time_str"] = " ".join(parts)
                            else:
                                self.state["remaining_time_str"] = "0m"
                            threshold = next_shutdown - dt.timedelta(minutes=pre_shutdown_minutes)
                            interval = fast_interval if now >= threshold else slow_interval
                        except Exception:
                            self.state["next_shutdown"] = None
                            self.state["remaining_seconds"] = None
                            self.state["remaining_time_str"] = None
                            self.state["timeout_limit"] = None
                            interval = slow_interval
                    else:
                        self.state["next_shutdown"] = None
                        self.state["remaining_seconds"] = None
                        self.state["remaining_time_str"] = None
                        self.state["timeout_limit"] = None

                    status_norm = (status or "").lower()
                    stop_statuses = {"terminated", "stopped", "stop", "failed"}
                    waiting_statuses = {"waiting"}

                    if status_norm in waiting_statuses:
                        logger.info("Container %s is Waiting (queued); continuing to poll.", name)
                        interval = min(interval, fast_interval)

                    if status_norm in stop_statuses:
                        logger.warning("Container %s status is %s; triggering restart.", name, status)
                        await self.restart_container()
                        break
                else:
                    logger.warning("Container %s not found; will retry soon.", name)
                    interval = fast_interval
            except Exception as exc:  # pragma: no cover - network/API errors
                logger.error("Monitor loop error: %s", exc)
                interval = fast_interval

            await asyncio.sleep(interval)
    def build_ssh_command(self, *, reload_config: bool = True) -> List[str]:
        """组装 SSH 命令：direct/jump/double。"""
        ssh_cfg = self._ssh_cfg(reload=reload_config)
        acs_cfg = self._acs_cfg(reload=reload_config)

        target_ip = self.state.get("container_ip") or ssh_cfg.get("container_ip")
        if not target_ip:
            target_ip = self.resolve_container_ip()
        if not target_ip:
            raise ValueError("Container IP unknown; not captured or configured.")

        mode = (ssh_cfg.get("mode") or "jump").lower()
        target_user = ssh_cfg.get("target_user", "root")
        bastion_host = ssh_cfg.get("bastion_host")
        bastion_user = ssh_cfg.get("bastion_user") or target_user
        ssh_port = ssh_cfg.get("port")
        password_login = ssh_cfg.get("password_login")
        password = ssh_cfg.get("password")
        forwards = ssh_cfg.get("forwards", [])
        local_open_port = ssh_cfg.get("local_open_port")
        container_open_port = ssh_cfg.get("container_open_port")

        def add_forwards(base: List[str], remote_host: str = "localhost") -> None:
            """仅按配置的 forwards 拼接 -L；不自动添加默认转发。"""
            for spec in forwards or []:
                local = spec.get("local")
                remote = spec.get("remote")
                if local and remote:
                    base.extend(["-L", f"{local}:{remote_host}:{remote}"])

        def add_port(base: List[str], port_value: Any) -> None:
            if port_value:
                base.extend(["-p", str(port_value)])

        known_hosts = "NUL" if os.name == "nt" else "/dev/null"
        keepalive = [
            "-o",
            "ServerAliveInterval=60",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            f"GlobalKnownHostsFile={known_hosts}",
        ]

        if mode == "double":
            if not bastion_host:
                raise ValueError("double mode requires ssh.bastion_host or ssh.remote_server_ip")
            revs = self._reverse_specs(ssh_cfg)
            if revs and any(spec.get("mid") is None for spec in revs):
                raise ValueError("double mode reverse forwarding needs mid (intermediate port) in reverse_forwards")

            outer: List[str] = ["ssh", "-T"] + keepalive
            add_port(outer, ssh_port)
            add_forwards(outer, default_remote=False)
            for spec in revs:
                outer.extend(["-R", f"{spec['mid']}:localhost:{spec['local']}"])
            outer.append(f"{bastion_user}@{bastion_host}")
            inner: List[str] = ["ssh", "-T", "-N"] + keepalive
            add_port(inner, ssh_cfg.get("container_port") or ssh_port)
            for spec in revs:
                inner.extend(["-R", f"{spec['remote']}:localhost:{spec['mid']}"])
            inner.append(f"{target_user}@{target_ip}")
            outer.append(" ".join(inner))
            cmd = outer
        else:
            cmd: List[str] = ["ssh", "-T", "-N"] + keepalive
            add_port(cmd, ssh_port)
            if mode == "jump":
                if not bastion_host:
                    raise ValueError("jump mode requires ssh.bastion_host or ssh.remote_server_ip")
                cmd.extend(["-J", f"{bastion_user}@{bastion_host}"])
            add_forwards(cmd)
            for spec in self._reverse_specs(ssh_cfg):
                cmd.extend(["-R", f"{spec['remote']}:localhost:{spec['local']}"])
            cmd.append(f"{target_user}@{target_ip}")

        if password_login and password:
            logger.info("Password login enabled; ensure automation handles password input safely.")
        return cmd

    def build_tunnel_command(self) -> List[str]:
        """生成带端口转发的 SSH 隧道命令。"""
        base = self.build_ssh_command()
        mode = (self._ssh_cfg(reload=False).get("mode") or "jump").lower()
        if mode == "double":
            return base
        return ["ssh", "-o", "ExitOnForwardFailure=yes", "-N"] + base[1:]

    def _forward_ports(self, ssh_cfg: Dict[str, Any]) -> List[int]:
        """收集需要本地监听的端口（仅 -L 正向转发）。"""
        ports: List[int] = []
        forwards = ssh_cfg.get("forwards") or []
        for spec in forwards:
            local = spec.get("local")
            if local:
                ports.append(int(local))
        return ports

    def _ports_available(self, ports: List[int]) -> bool:
        """尝试绑定端口以检查占用。"""
        import socket

        for p in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("127.0.0.1", p))
                except OSError:
                    logger.error("Local port %s is in use; attempting cleanup then retry.", p)
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
                logger.warning("Killing local ssh occupying port, pid=%s", pid)
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except psutil.TimeoutExpired:
                    proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _remote_kill_ports_on_host(
        self,
        *,
        host: str,
        user: str,
        ports: List[int],
        ssh_port: Optional[int],
        jump: Optional[str] = None,
        allow_sudo: bool = True,
    ) -> None:
        """在远端主机上强杀占用指定端口的进程，优先 netstat。"""
        if not host or not user or not ports:
            return
        cmd = ["ssh", "-T"]
        if jump:
            cmd += ["-J", jump]
        if ssh_port:
            cmd += ["-p", str(ssh_port)]
        cmd.append(f"{user}@{host}")
        cmd += ["bash", "-s"]
        plist = " ".join(str(p) for p in ports)
        script = """
if command -v sudo >/dev/null 2>&1 && {use_sudo}; then PREF="sudo -n"; else PREF=""; fi
for p in {plist}; do
  if command -v netstat >/dev/null 2>&1; then
    $PREF netstat -tnlp 2>/dev/null | awk -v port=":$p" '$4 ~ port"$" {{for(i=1;i<=NF;i++){{if($i~"/"){{split($i,a,"/"); print a[1]}}}}}}' | xargs -r $PREF kill -9
  elif command -v ss >/dev/null 2>&1; then
    $PREF ss -ltnp | awk -F'pid=' '$0 ~ /:$p/ {{print $2}}' | awk '{{print $1}}' | tr -d ',' | xargs -r $PREF kill -9
  fi
  if command -v fuser >/dev/null 2>&1; then
    $PREF fuser -k ${{p}}/tcp
  fi
done
""".format(plist=plist, use_sudo="true" if allow_sudo else "false")
        try:
            res = subprocess.run(
                cmd,
                input=script.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=8,
                check=False,
            )
            out = res.stdout.decode(errors="ignore").strip()
            err = res.stderr.decode(errors="ignore").strip()
            if res.returncode != 0:
                logger.debug("Remote port cleanup returned code %s", res.returncode)
                if err:
                    logger.debug("Remote port cleanup stderr: %s", err)
            elif out:
                logger.debug("Remote port cleanup output: %s", out)
        except Exception as exc:
            logger.info("Remote port cleanup failed: %s", exc)
            return

    def _remote_cleanup_ports(self, ports: List[int]) -> None:
        """尝试在跳板/容器上清理占用同端口的进程。"""
        ssh_cfg = self._ssh_cfg(reload=True)
        mode = (ssh_cfg.get("mode") or "jump").lower()
        bastion_host = ssh_cfg.get("bastion_host") or ssh_cfg.get("remote_server_ip")
        bastion_user = ssh_cfg.get("bastion_user") or ssh_cfg.get("target_user") or "root"
        target_user = ssh_cfg.get("target_user") or "root"
        ssh_port = ssh_cfg.get("port")
        container_port = ssh_cfg.get("container_port") or ssh_port
        target_ip = self.state.get("container_ip") or ssh_cfg.get("container_ip")

        if bastion_host:
            self._remote_kill_ports_on_host(
                host=bastion_host,
                user=bastion_user,
                ports=ports,
                ssh_port=ssh_port,
                jump=None,
            )
        if target_ip:
            jump = f"{bastion_user}@{bastion_host}" if bastion_host and mode in {"jump", "double"} else None
            self._remote_kill_ports_on_host(
                host=target_ip,
                user=target_user,
                ports=ports,
                ssh_port=container_port,
                jump=jump,
            )

    def _reverse_cleanup_ports(self, remote_ports: List[int], intermediate_ports: List[int], ssh_cfg: Dict[str, Any], target_ip: Optional[str]) -> None:
        """反向转发端口清理：跳板用中间端口，容器用远端端口。"""
        mode = (ssh_cfg.get("mode") or "jump").lower()
        bastion_host = ssh_cfg.get("bastion_host") or ssh_cfg.get("remote_server_ip")
        bastion_user = ssh_cfg.get("bastion_user") or ssh_cfg.get("target_user") or "root"
        target_user = ssh_cfg.get("target_user") or "root"
        ssh_port = ssh_cfg.get("port")
        container_port = ssh_cfg.get("container_port") or ssh_port

        if bastion_host and intermediate_ports:
            self._remote_kill_ports_on_host(
                host=bastion_host,
                user=bastion_user,
                ports=intermediate_ports,
                ssh_port=ssh_port,
                jump=None,
                allow_sudo=False,
            )
        if target_ip and remote_ports:
            jump = f"{bastion_user}@{bastion_host}" if bastion_host and mode in {"jump", "double"} else None
            self._remote_kill_ports_on_host(
                host=target_ip,
                user=target_user,
                ports=remote_ports,
                ssh_port=container_port,
                jump=jump,
                allow_sudo=True,
            )

    def _reverse_specs(self, ssh_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """解析反向转发规范：支持字典或 'local:remote[:mid]' 字符串。"""
        revs = ssh_cfg.get("reverse_forwards") or []
        specs: List[Dict[str, Any]] = []

        def _parse(item: Any) -> Optional[Dict[str, Any]]:
            if isinstance(item, str):
                parts = item.split(":")
                if len(parts) not in (2, 3):
                    return None
                local, remote = parts[0], parts[1]
                mid = parts[2] if len(parts) == 3 else None
                return {
                    "local": int(local),
                    "remote": int(remote),
                    "mid": int(mid) if mid else None,
                }
            if isinstance(item, dict):
                local = item.get("local")
                remote = item.get("remote")
                mid = item.get("intermediate") or item.get("mid")
                if local is None or remote is None:
                    return None
                return {
                    "local": int(local),
                    "remote": int(remote),
                    "mid": int(mid) if mid else None,
                }
            return None

        for item in revs:
            parsed = _parse(item)
            if parsed:
                specs.append(parsed)
        return specs
    async def _ensure_ports_free(self, ports: List[int], retries: int = 3, delay: float = 1.0) -> bool:
        """隧道重连前多次尝试释放端口。"""
        for attempt in range(retries):
            if self._ports_available(ports):
                return True
            await self.stop_tunnel()
            self._kill_ssh_on_ports(ports)
            self._remote_cleanup_ports(ports)
            if attempt < retries - 1:
                await asyncio.sleep(delay)
        return self._ports_available(ports)

    async def start_tunnel(self) -> None:
        """启动 SSH 隧道（若未运行）。"""
        async with self._proc_lock:
            if self._tunnel_process and self._tunnel_process.returncode is None:
                return
            try:
                ssh_cfg = self._ssh_cfg(reload=True)
                target_ip = self.state.get("container_ip") or ssh_cfg.get("container_ip")
                if not target_ip:
                    try:
                        self.container_client.login()
                    except Exception as exc:
                        logger.error("Login failed before resolving container IP: %s", exc)
                    target_ip = (
                        self.state.get("container_ip")
                        or self.resolve_container_ip(force_login=False)
                        or self.resolve_container_ip(force_login=True)
                    )
                    if not target_ip:
                        raise ValueError("Container IP unknown; cannot start tunnel.")
                reverse_specs = self._reverse_specs(ssh_cfg)
                ports = self._forward_ports(ssh_cfg)
                remote_ports = [spec["remote"] for spec in reverse_specs if spec.get("remote")]
                intermediate_ports = [spec["mid"] for spec in reverse_specs if spec.get("mid")]
                if reverse_specs:
                    logger.info("Cleaning remote ports before starting: container=%s, intermediate=%s", remote_ports, intermediate_ports)
                    self._reverse_cleanup_ports(remote_ports, intermediate_ports, ssh_cfg, target_ip)
                    await asyncio.sleep(1.0)
                if ports and not await self._ensure_ports_free(ports):
                    self.state["tunnel_status"] = "error"
                    return
                cmd = self.build_tunnel_command()
            except Exception as exc:
                logger.error("Cannot build tunnel command: %s", exc)
                self.state["tunnel_status"] = "error"
                return

            logger.info("Starting SSH tunnel: %s", " ".join(cmd))
            proc = await asyncio.create_subprocess_exec(*cmd)
            self._tunnel_process = proc
            self.state["tunnel_status"] = "running"
            self._tunnel_started_once = True

    async def stop_tunnel(self) -> None:
        """停止隧道并更新状态。"""
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
            self.state["tunnel_last_exit"] = dt.datetime.now()
            self.state["tunnel_status"] = "stopped"
            self._tunnel_process = None

    async def restart_tunnel(self) -> None:
        """重启隧道刷新转发与端口。"""
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
                if rc == 0:
                    self._tunnel_failure_count = 0
                    logger.info("SSH tunnel exited normally.")
                else:
                    self._tunnel_failure_count += 1
                    logger.warning(
                        "SSH tunnel exit code %s; will restart soon. (consecutive failures: %s)",
                        rc,
                        self._tunnel_failure_count,
                    )
                    if self._tunnel_failure_count >= 3:
                        name = self._acs_cfg(reload=True).get("container_name")
                        logger.warning(
                            "SSH tunnel failed >=3 times; refreshing container IP via API (container: %s).",
                            name,
                        )
                        ip = self.resolve_container_ip(force_login=True)
                        if not ip:
                            # 如果 IP 仍未获取但登录正常，可尝试读取容器状态，异常则触发重启
                            try:
                                info = self.container_client.get_container_instance_info_by_name(name) if name else None
                            except Exception as exc:  # pragma: no cover - network errors
                                logger.error("Failed to fetch container status after tunnel failures: %s", exc)
                                info = None
                            status = (info or {}).get("status")
                            unhealthy = status and status.lower() not in {
                                "running",
                                "pending",
                                "deploying",
                                "queued",
                                "queue",
                                "starting",
                            }
                            if unhealthy:
                                logger.warning("Container %s status %s appears unhealthy; attempting restart.", name, status)
                                await self.restart_container()
                        self._tunnel_failure_count = 0
            except Exception as exc:  # pragma: no cover - subprocess errors
                logger.error("SSH tunnel crashed: %s", exc)
            finally:
                await self.stop_tunnel()
            await asyncio.sleep(3)

    async def shutdown(self) -> None:
        """通知循环退出并关闭隧道。"""
        self._stop_requested = True
        await self.stop_tunnel()

    def snapshot(self) -> Dict[str, Any]:
        """获取当前状态（供 Web UI 展示）。"""
        snap = dict(self.state)
        if not snap.get("container_ip"):
            try:
                ssh_cfg = self._ssh_cfg(reload=False)
                fallback_ip = ssh_cfg.get("container_ip") if isinstance(ssh_cfg, dict) else None
                if fallback_ip:
                    snap["container_ip"] = fallback_ip
            except Exception:
                pass
        return snap

    async def prepare_on_start(self, wait_interval: int = 5, start_timeout: int = 300) -> None:
        """启动阶段：登录后检查容器状态，Waiting 等待，Stopped 重启，Running 继续。"""
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.warning("acs.container_name not configured; skip startup check.")
            return

        try:
            self.container_client.login()
            logger.info("Logged in to ACS for startup check.")
        except Exception as exc:
            logger.error("Login failed during startup preparation: %s", exc)
            return

        def _fetch_info() -> Optional[Dict[str, Any]]:
            try:
                return self.container_client.get_container_instance_info_by_name(name)
            except Exception as exc:
                logger.error("Failed to fetch container info for %s: %s", name, exc)
                return None

        info = _fetch_info()
        if not info:
            logger.warning("Container %s not found during startup check.", name)
            return

        status = (info.get("status") or "").lower()
        start_time = info.get("startTime") or info.get("createTime")
        self.update_container_status(info.get("status"), start_time)
        ip = info.get("instanceIp")
        if ip:
            await self.handle_new_ip(ip)

        async def _wait_for_running() -> None:
            deadline = dt.datetime.now() + dt.timedelta(seconds=start_timeout)
            while dt.datetime.now() < deadline and not self._stop_requested:
                latest = _fetch_info()
                if not latest:
                    await asyncio.sleep(wait_interval)
                    continue
                status_local = (latest.get("status") or "").lower()
                self.update_container_status(latest.get("status"), latest.get("startTime") or latest.get("createTime"))
                ip_local = latest.get("instanceIp")
                if ip_local:
                    await self.handle_new_ip(ip_local)
                if status_local == "running":
                    logger.info("Container %s is now running; continue startup.", name)
                    return
                if status_local == "waiting":
                    logger.info("Container %s still waiting; polling...", name)
                else:
                    logger.info("Container %s status=%s; waiting for running...", name, status_local)
                await asyncio.sleep(wait_interval)
            logger.warning("Timeout waiting for container %s to reach running state.", name)

        if status == "waiting":
            logger.info("Container %s is Waiting; polling until it starts.", name)
            await _wait_for_running()
        elif status in {"terminated", "stopped", "stop", "failed"}:
            logger.warning("Container %s is stopped (%s); attempting to start.", name, status)
            await self.restart_container()
            await _wait_for_running()
        else:
            logger.info("Container %s status is %s; continuing startup.", name, status or "unknown")

    def _acs_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("acs", default={}, reload=reload)

    def _ssh_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("ssh", default={}, reload=reload)

    def bind_state_store(self, state_store: RuntimeStateStore) -> None:
        """Attach external runtime state store (for non-config data)."""
        self.state_store = state_store

    def _restart_state(self) -> Dict[str, Any]:
        if not self.state_store:
            return {}
        try:
            return self.state_store.read_container(self.container_id)
        except Exception:
            return {}

    def _restart_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        cfg = self.store.get_section("restart", default={}, reload=reload)
        strategy = (cfg.get("strategy") or "restart").lower()
        state = self._restart_state()
        create_count = state.get("create_count") or 0
        try:
            create_count = int(create_count)
        except Exception:
            create_count = 0
        return {
            "strategy": strategy,
            "create_count": create_count,
            "last_created_at": state.get("last_created_at"),
            "last_created_name": state.get("last_created_name"),
        }

    def _persist_restart_cfg(self, cfg: Dict[str, Any]) -> None:
        if not self.state_store:
            return
        try:
            self.state_store.update_container(
                self.container_id,
                {
                    "create_count": cfg.get("create_count"),
                    "last_created_at": cfg.get("last_created_at"),
                    "last_created_name": cfg.get("last_created_name"),
                },
            )
        except Exception as exc:
            logger.warning("Failed to persist restart state: %s", exc)
