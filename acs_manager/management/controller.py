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

logger = logging.getLogger(__name__)


class ContainerManager:
    """
    负责：
    - 通过 ACS API 跟踪容器状态（Running / Waiting / Stopped 等）；
    - 计算开始时间 + 超时时间得到预计自动停止时间与剩余时间；
    - 维护 SSH 隧道（直连 / 跳板 -J / 双层 SSH）和本地端口转发；
    - 在容器停止后自动调用重启接口，并在 IP 变化时刷新隧道。
    """

    def __init__(self, store: ConfigStore, container_client: Optional[ContainerClient] = None) -> None:
        self.store = store
        self.container_client = container_client or ContainerClient(store)
        self.state: Dict[str, Any] = {
            "container_ip": None,
            "next_shutdown": None,
            "remaining_seconds": None,
            "remaining_time_str": None,
            "timeout_limit": None,
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
        self._tunnel_failure_count = 0

    # -------------------------------------------------------------------------
    # 容器 IP 与状态
    # -------------------------------------------------------------------------
    async def handle_new_ip(self, ip: str) -> None:
        """
        捕获到新的容器 IP 时更新状态；如果 IP 真正发生变化且隧道已经建立过，则重启隧道。
        """
        old_ip = self.state.get("container_ip")
        self.state["last_seen"] = dt.datetime.now()

        # IP 未变化且隧道已经跑过：仅当心跳，避免重复重启
        if old_ip == ip and self._tunnel_started_once:
            logger.debug("容器 IP 未变化(%s)，仅更新 last_seen。", ip)
            return

        self.state["container_ip"] = ip

        # 首次拿到 IP：让 maintain_tunnel 执行第一次启动，不抢它的流程
        if not self._tunnel_started_once:
            logger.info("容器 IP 首次捕获为 %s，等待隧道初始化。", ip)
            return

        # IP 真实变化：重启隧道
        logger.info("容器 IP 更新为 %s（旧值: %s），重启隧道。", ip, old_ip)
        await self.restart_tunnel()

    def update_container_status(self, status: Optional[str], start_time: Optional[str]) -> None:
        self.state["container_status"] = status
        self.state["container_start_time"] = start_time

    def resolve_container_ip(self, *, force_login: bool = True) -> Optional[str]:
        """
        当 IP 未知时，通过 ACS API 自动获取容器 IP。
        会根据配置的 acs.container_name 查询最新的相关任务。
        """
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
        except Exception as exc:  # pragma: no cover - 网络/API 异常
            logger.error("通过 API 获取容器 %s 信息失败: %s", name, exc)
            return None

        if info and info.get("instanceIp"):
            ip = info["instanceIp"]
            self.state["container_ip"] = ip
            self.state["last_seen"] = dt.datetime.now()
            logger.info("通过 API 自动获取容器 IP: %s", ip)
            return ip

        logger.warning("无法通过 API 获取容器 %s 的 IP。", name)
        return None

    async def ensure_running(self) -> None:
        """监控循环检测到容器停止时调用，立即尝试重启。"""
        await self.restart_container()

    async def prepare_on_start(self, poll_interval: int = 10) -> None:
        """
        程序启动阶段的容器状态预检查：

        - 先登录 ACS，确保网页 cookie 有效；
        - 根据容器名称拉取当前状态：
          * Waiting：表示排队，持续等待并轮询；
          * Running：直接继续后续启动流程；
          * Stopped/Terminated/Failed：调用重启接口启动，再等待到 Running。
        """
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.info("未配置 acs.container_name，跳过启动前的容器状态检查。")
            return

        # 先登录，保证 cookie 有效
        try:
            self.container_client.login()
        except Exception as exc:  # pragma: no cover - 网络异常
            logger.error("启动流程登录 ACS 失败，跳过预检查：%s", exc)
            return

        stop_statuses = {"terminated", "stopped", "stop", "failed"}
        waiting_statuses = {"waiting"}

        while not self._stop_requested:
            try:
                info = self.container_client.get_container_instance_info_by_name(name)
            except Exception as exc:  # pragma: no cover
                logger.error("启动前获取容器 %s 状态失败：%s", name, exc)
                await asyncio.sleep(poll_interval)
                continue

            if not info:
                logger.warning("启动前未找到容器 %s，等待后重试。", name)
                await asyncio.sleep(poll_interval)
                continue

            status = info.get("status")
            start_time_str = info.get("startTime") or info.get("createTime")
            self.update_container_status(status, start_time_str)
            ip = info.get("instanceIp")
            if ip:
                await self.handle_new_ip(ip)

            status_norm = (status or "").lower()
            if status_norm in waiting_statuses:
                logger.info("启动前容器 %s 状态 Waiting（排队），等待调度。", name)
                await asyncio.sleep(poll_interval)
                continue

            if status_norm in stop_statuses:
                logger.warning("启动前容器 %s 状态 %s，尝试重启容器。", name, status)
                await self.restart_container()
                # 给 ACS 一点时间拉起实例
                await asyncio.sleep(poll_interval)
                continue

            # 认为已经在运行或正在部署，继续后续流程
            logger.info("启动前容器 %s 状态 %s，继续后续启动流程。", name, status or "未知")
            break

    async def restart_container(self) -> None:
        """调用 ACS 重启接口 /api/instance-service/task/actions/restart。"""
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.error("未配置 acs.container_name，无法重启容器。")
            return

        try:
            task = self.container_client.find_instance_by_name(name)
        except Exception as exc:
            logger.error("查询容器 %s 失败，无法重启：%s", name, exc)
            return

        if not task:
            logger.error("未找到容器 %s，对应的任务记录为空，无法重启。", name)
            return

        task_id = task.get("instanceServiceId") or task.get("id")
        if not task_id:
            logger.error("容器 %s 缺少 instanceServiceId，无法重启。", name)
            return

        logger.warning("尝试重启容器 %s（task id: %s）。", name, task_id)
        try:
            resp = self.container_client.restart_task(task_id)
        except Exception as exc:
            logger.error("调用重启接口失败: %s", exc)
            return

        if str(resp.get("code")) == "0":
            logger.info("重启请求成功: %s", resp)
            self.state["last_restart"] = dt.datetime.now()
        else:
            logger.error("重启请求返回失败: %s", resp)

    # -------------------------------------------------------------------------
    # 时间解析与容器生命周期监控
    # -------------------------------------------------------------------------
    def _parse_start_time(self, value: Optional[str]) -> Optional[dt.datetime]:
        if not value:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return dt.datetime.strptime(value, fmt)
            except ValueError:
                continue
        return None

    def _parse_remaining_time_str(self, value: Optional[str]) -> Optional[int]:
        """
        解析 ACS 提供的 remainingTime 文本，例如 "14d 23h 48m"，返回秒数。
        仅作为展示参考，真正的停止时间以 startTime + timeoutLimit 为准。
        """
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

    async def monitor_container(
        self,
        *,
        pre_shutdown_minutes: int = 10,
        slow_interval: int = 300,
        fast_interval: int = 30,
    ) -> None:
        """
        周期检查容器状态；接近超时时缩短检查间隔，停止时立即重启。
        """
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.warning("未配置 acs.container_name，容器监控循环退出。")
            return

        stop_statuses = {"terminated", "stopped", "stop", "failed"}
        waiting_statuses = {"waiting"}

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

                    # 使用 startTime + timeoutLimit 计算预计自动停止时间和剩余时间
                    start_dt = self._parse_start_time(start_time_str)
                    timeout_str = info.get("timeoutLimit")
                    now = dt.datetime.now()
                    if start_dt and timeout_str:
                        try:
                            self.state["timeout_limit"] = timeout_str
                            hours, minutes, seconds = timeout_str.split(":")
                            delta = dt.timedelta(
                                hours=int(hours),
                                minutes=int(minutes),
                                seconds=int(seconds),
                            )
                            next_shutdown = start_dt + delta
                            self.state["next_shutdown"] = next_shutdown.strftime("%Y-%m-%d %H:%M:%S")
                            remaining = (next_shutdown - now).total_seconds()
                            remaining_sec = int(remaining) if remaining > 0 else 0
                            self.state["remaining_seconds"] = remaining_sec

                            # 生成可读的剩余时间字符串
                            if remaining_sec > 0:
                                days = remaining_sec // 86400
                                hours_left = (remaining_sec % 86400) // 3600
                                mins_left = (remaining_sec % 3600) // 60
                                parts: List[str] = []
                                if days > 0:
                                    parts.append(f"{days} 天")
                                if hours_left > 0:
                                    parts.append(f"{hours_left} 小时")
                                if mins_left > 0 or not parts:
                                    parts.append(f"{mins_left} 分钟")
                                self.state["remaining_time_str"] = " ".join(parts)
                            else:
                                self.state["remaining_time_str"] = "0 分钟"

                            # 接近停止时间，使用快速轮询
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

                    # Waiting 视为排队状态，不触发重启，但加快轮询
                    if status_norm in waiting_statuses:
                        logger.info("容器 %s 当前状态为 Waiting（排队），等待调度。", name)
                        interval = min(interval, fast_interval)

                    # 停止 / 失败：触发重启
                    if status_norm in stop_statuses:
                        logger.warning("容器 %s 状态为 %s，触发自动重启。", name, status)
                        await self.restart_container()
                        break
                else:
                    logger.warning("容器 %s 未找到，将使用快速轮询重试。", name)
                    interval = fast_interval
            except Exception as exc:  # pragma: no cover
                logger.error("监控循环异常: %s", exc)
                interval = fast_interval

            await asyncio.sleep(interval)

    # -------------------------------------------------------------------------
    # SSH 隧道构建与端口清理
    # -------------------------------------------------------------------------
    def _forward_ports(self, ssh_cfg: Dict[str, Any]) -> List[int]:
        """
        解析 ssh.forwards / ssh.local_open_port / ssh.container_open_port，
        返回本地需要占用的端口列表。
        """
        ports: List[int] = []
        forwards = ssh_cfg.get("forwards") or []
        for spec in forwards:
            local = spec.get("local")
            if isinstance(local, int):
                ports.append(local)
        # 兼容默认本地端口配置
        if ssh_cfg.get("local_open_port"):
            ports.append(int(ssh_cfg["local_open_port"]))
        # 去重
        return sorted(set(ports))

    def _reverse_specs(self, ssh_cfg: Dict[str, Any]) -> List[Dict[str, int]]:
        """
        解析 ssh.reverse_forwards / ssh.local_open_port / ssh.container_open_port / ssh.intermediate_port，
        返回 [{\"local\": 本地端口, \"remote\": 容器端口, \"mid\": 跳板中间端口}, ...]。
        """
        specs: List[Dict[str, int]] = []
        reverse = ssh_cfg.get("reverse_forwards") or []
        for item in reverse:
            try:
                local = int(item["local"])
                remote = int(item["remote"])
                mid_raw = item.get("mid")
                mid = int(mid_raw) if mid_raw is not None else None
            except Exception:
                continue
            spec: Dict[str, int] = {"local": local, "remote": remote}
            if mid is not None:
                spec["mid"] = mid
            specs.append(spec)

        # 如果没有显式配置，尝试使用默认的 local_open_port/container_open_port/intermediate_port
        if not specs and ssh_cfg.get("local_open_port") and ssh_cfg.get("container_open_port"):
            local = int(ssh_cfg["local_open_port"])
            remote = int(ssh_cfg["container_open_port"])
            mid_raw = ssh_cfg.get("intermediate_port")
            spec = {"local": local, "remote": remote}
            if mid_raw:
                spec["mid"] = int(mid_raw)
            specs.append(spec)
        return specs

    def _find_local_port_pids(self, port: int) -> List[int]:
        """查找本地占用指定端口的进程 PID 列表。"""
        pids: List[int] = []
        for conn in psutil.net_connections(kind="tcp"):
            if not conn.laddr:
                continue
            if conn.laddr.port != port:
                continue
            if conn.pid is not None:
                pids.append(conn.pid)
        return pids

    async def _ensure_ports_free(self, ports: List[int]) -> bool:
        """
        确保本地端口未被占用。
        如被占用，尝试强制结束同一用户的 ssh 进程后重试一次。
        """
        username = getpass.getuser()
        for port in ports:
            pids = self._find_local_port_pids(port)
            if not pids:
                continue

            logger.warning("本地端口 %s 已被占用，尝试自动清理同一用户的 ssh 进程。", port)
            targets: List[int] = []
            for pid in pids:
                try:
                    proc = psutil.Process(pid)
                    if proc.username() == username and "ssh" in proc.name().lower():
                        targets.append(pid)
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

            # 再检查一次
            await asyncio.sleep(1)
            if self._find_local_port_pids(port):
                logger.error("本地端口 %s 仍被占用，无法启动隧道。", port)
                return False

        return True

    def _remote_kill_ports_on_host(
        self,
        *,
        host: str,
        user: str,
        ports: List[int],
        ssh_port: Optional[int],
        jump: Optional[str] = None,
    ) -> None:
        """
        在远端主机上强杀占用指定端口的进程（优先使用 netstat / ss / fuser）。
        仅用于清理远端反向端口转发残留。
        """
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
        script = f"""
if command -v sudo >/dev/null 2>&1; then PREF="sudo -n"; else PREF=""; fi
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
"""
        try:
            res = subprocess.run(
                cmd,
                input=script.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            out = res.stdout.decode(errors="ignore").strip()
            err = res.stderr.decode(errors="ignore").strip()
            if res.returncode != 0:
                logger.debug("远端端口清理返回码 %s", res.returncode)
                if err:
                    logger.debug("远端端口清理 stderr: %s", err)
            elif out:
                logger.debug("远端端口清理输出: %s", out)
        except Exception as exc:
            logger.info("远端端口清理失败: %s", exc)

    def _remote_cleanup_ports(self, ports: List[int]) -> None:
        """
        在跳板机和容器上尝试清理占用相同端口的进程。
        仅在需要保证本地端口 <-> 远端端口一一对应时使用。
        """
        if not ports:
            return

        ssh_cfg = self._ssh_cfg(reload=True)
        mode = (ssh_cfg.get("mode") or "jump").lower()
        bastion_host = ssh_cfg.get("bastion_host") or ssh_cfg.get("remote_server_ip")
        bastion_user = ssh_cfg.get("bastion_user") or ssh_cfg.get("target_user") or "root"
        target_user = ssh_cfg.get("target_user") or "root"
        ssh_port = ssh_cfg.get("port")
        container_port = ssh_cfg.get("container_per
