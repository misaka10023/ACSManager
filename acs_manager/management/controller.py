from __future__ import annotations

import asyncio
import datetime as dt
import getpass
import logging
import subprocess
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
                try:
                    info = self.container_client.get_container_instance_info_by_name(name)
                except Exception as exc:
                    # 如果是认证失败，尝试重新登录一次
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
        ssh_port = ssh_cfg.get("port")
        password_login = ssh_cfg.get("password_login")
        password = ssh_cfg.get("password")
        forwards = ssh_cfg.get("forwards", [])
        local_open_port = ssh_cfg.get("local_open_port")
        container_open_port = ssh_cfg.get("container_open_port")

        def add_forwards(
            base: List[str],
            remote_host: str = "localhost",
            *,
            default_remote: bool = False,
        ) -> None:
            """
            默认转发（无自定义 forwards）使用远程转发 -R，令容器端口可见；
            显式 forwards 列表仍按 -L 行为（本地 -> 远端）。
            """
            if forwards:
                for spec in forwards:
                    local = spec.get("local")
                    remote = spec.get("remote")
                    if local and remote:
                        base.extend(["-L", f"{local}:{remote_host}:{remote}"])
                return
            if default_remote and local_open_port and container_open_port:
                base.extend(["-R", f"{container_open_port}:localhost:{local_open_port}"])

        def add_port(base: List[str], port_value: Any) -> None:
            if port_value:
                base.extend(["-p", str(port_value)])

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
            "UserKnownHostsFile=/dev/null",
        ]

        if mode == "double":
            if not bastion_host:
                raise ValueError("double 模式需要 ssh.bastion_host 或 ssh.remote_server_ip。")
            revs = self._reverse_specs(ssh_cfg)
            if any(spec.get("mid") is None for spec in revs):
                raise ValueError("double 模式的反向转发需要 intermediate_port 或每条 reverse_forwards.intermediate。")

            outer: List[str] = ["ssh", "-T"] + keepalive
            add_port(outer, ssh_port)
            # 本地正向转发（如有）在外层执行
            add_forwards(outer, default_remote=False)
            # 外层负责将本地端口暴露到跳板的中间端口
            for spec in revs:
                outer.extend(["-R", f"{spec['mid']}:localhost:{spec['local']}"])
            outer.append(f"{bastion_user}@{bastion_host}")
            # 内层保持连接并在容器侧打开反向转发
            inner: List[str] = ["ssh", "-T", "-N"] + keepalive
            add_port(inner, ssh_cfg.get("container_port") or ssh_port)
            # 内层将容器端口指向跳板中间端口
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
                    raise ValueError("jump 模式需要 ssh.bastion_host 或 ssh.remote_server_ip。")
                cmd.extend(["-J", f"{bastion_user}@{bastion_host}"])
            add_forwards(cmd, default_remote=False)
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
        """
        收集需要本地监听的端口（仅针对 -L 正向转发）。
        反向转发 -R 不在本地绑定端口，不需要检测占用。
        """
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
        """在远端主机上强杀占用指定端口的进程（优先使用 netstat，必要时 sudo）。"""
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
                logger.info("远端端口清理返回码 %s", res.returncode)
                if err:
                    logger.debug("远端端口清理 stderr: %s", err)
            elif out:
                logger.debug("远端端口清理输出: %s", out)
        except Exception as exc:
            logger.info("远端端口清理失败: %s", exc)
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
        """
        构造反向转发规格：
        - reverse_forwards 列表项：local(本地)->remote(容器)，可选 intermediate(跳板)
        - 若 reverse_forwards 为空，则默认使用 container_open_port/local_open_port
        """
        local_open_port = ssh_cfg.get("local_open_port")
        container_open_port = ssh_cfg.get("container_open_port")
        intermediate_port = ssh_cfg.get("intermediate_port")
        revs = ssh_cfg.get("reverse_forwards") or []
        specs: List[Dict[str, Any]] = []
        if not revs and local_open_port and container_open_port:
            revs = [{"local": local_open_port, "remote": container_open_port}]
        for spec in revs:
            local = spec.get("local")
            remote = spec.get("remote")
            mid = spec.get("intermediate") or intermediate_port
            specs.append({"local": int(local), "remote": int(remote), "mid": int(mid) if mid else None})
        return specs

    async def _ensure_ports_free(self, ports: List[int], retries: int = 3, delay: float = 1.0) -> bool:
        """在隧道重连时，重试释放端口后再启动。"""
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
                        logger.error("获取容器 IP 前登录失败: %s", exc)
                    target_ip = self.state.get("container_ip") or self.resolve_container_ip(force_login=False) or self.resolve_container_ip(force_login=True)
                    if not target_ip:
                        raise ValueError("容器 IP 未知，无法启动隧道。")
                reverse_specs = self._reverse_specs(ssh_cfg)
                ports = self._forward_ports(ssh_cfg)
                # 远程反向转发端口预清理（容器端 & 跳板中间端口）
                remote_ports = [spec["remote"] for spec in reverse_specs if spec.get("remote")]
                intermediate_ports = [spec["mid"] for spec in reverse_specs if spec.get("mid")]
                if reverse_specs:
                    logger.info("尝试清理远端端口: container=%s, intermediate=%s", remote_ports, intermediate_ports)
                    self._reverse_cleanup_ports(remote_ports, intermediate_ports, ssh_cfg, target_ip)
                    # 短暂停顿让远端清理完成
                    await asyncio.sleep(1.0)
                # 每次启动前都确保端口可用，并尝试清理同用户的 ssh 占用
                if ports and not await self._ensure_ports_free(ports):
                    self.state["tunnel_status"] = "error"
                    return
                cmd = self.build_tunnel_command()
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
