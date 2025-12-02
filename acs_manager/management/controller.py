# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import datetime as dt
import getpass
import logging
import os
import socket
import subprocess
from asyncio.subprocess import Process
from typing import Any, Dict, List, Optional

import psutil

from acs_manager.config.store import ConfigStore
from acs_manager.container.client import ContainerClient

logger = logging.getLogger(__name__)


class ContainerManager:
    """?? ACS ???????IP ??? SSH ?????"""

    def __init__(
        self,
        store: ConfigStore,
        container_client: Optional[ContainerClient] = None,
    ) -> None:
        self.store = store
        self.container_client = container_client or ContainerClient(store)

        # ? WebUI ?????????
        self.state: Dict[str, Any] = {
            "container_ip": None,
            "next_shutdown": None,
            "remaining_seconds": None,
            "timeout_limit": None,
            "remaining_time_str": None,
            "last_restart": None,
            "last_seen": None,
            "tunnel_status": "stopped",
            "tunnel_last_exit": None,
            "container_status": None,
            "container_start_time": None,
        }

        # SSH ????????
        self._tunnel_process: Optional[Process] = None
        self._proc_lock = asyncio.Lock()
        self._stop_requested = False
        self._tunnel_started_once = False
        self._tunnel_failure_count = 0

    # ------------------------------------------------------------------
    # ????
    # ------------------------------------------------------------------

    def _acs_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("acs", default={}, reload=reload)

    def _ssh_cfg(self, *, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("ssh", default={}, reload=reload)

    # ------------------------------------------------------------------
    # ?? IP / ????
    # ------------------------------------------------------------------

    async def handle_new_ip(self, ip: str) -> None:
        """???????? IP ???????? IP ??????????????????"""
        old_ip = self.state.get("container_ip")
        self.state["last_seen"] = dt.datetime.now()

        # IP ??????????????????????
        if old_ip == ip and self._tunnel_started_once:
            logger.debug("?? IP ???(%s)???? last_seen?", ip)
            return

        self.state["container_ip"] = ip

        # ???? IP??? maintain_tunnel ?????????????
        if not self._tunnel_started_once:
            logger.info("?? IP ????? %s?????????", ip)
            return

        # IP ?????????
        logger.info("?? IP ??? %s???: %s???????", ip, old_ip)
        await self.restart_tunnel()

    def update_container_status(
        self,
        status: Optional[str],
        start_time: Optional[str],
    ) -> None:
        """???????????????"""
        self.state["container_status"] = status
        self.state["container_start_time"] = start_time

    def resolve_container_ip(self, *, force_login: bool = True) -> Optional[str]:
        """? IP ?????? ACS API ?????"""
        name = self._acs_cfg(reload=True).get("container_name")
        if not name:
            logger.warning("??? acs.container_name??????? IP?")
            return None

        if force_login:
            try:
                self.container_client.login()
            except Exception as exc:  # pragma: no cover - ????
                logger.error("????????? IP ??: %s", exc)
                return None

        try:
            info = self.container_client.get_container_instance_info_by_name(name)
        except Exception as exc:  # pragma: no cover - ????
            logger.error("?? API ???? %s ????: %s", name, exc)
            return None

        if info and info.get("instanceIp"):
            ip = info["instanceIp"]
            self.state["container_ip"] = ip
            self.state["last_seen"] = dt.datetime.now()
            logger.info("?? API ?????? IP: %s", ip)
            return ip

        logger.warning("???? API ???? %s ? IP?", name)
        return None

    async def ensure_running(self) -> None:
        """??????????????????"""
        await self.restart_container()

    async def prepare_on_start(self, poll_interval: int = 10) -> None:
        """???????????????????????? Waiting / Stopped??"""
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.info("??? acs.container_name?????????")
            return

        # ?????? cookie
        try:
            self.container_client.login()
        except Exception as exc:  # pragma: no cover - ????
            logger.error("????? ACS ??: %s", exc)
            return

        stop_statuses = {"terminated", "stopped", "stop", "failed"}
        waiting_statuses = {"waiting"}

        while not self._stop_requested:
            try:
                info = self.container_client.get_container_instance_info_by_name(name)
            except Exception as exc:  # pragma: no cover - ??/API ??
                logger.error("???? %s ????: %s", name, exc)
                await asyncio.sleep(poll_interval)
                continue

            if not info:
                logger.warning("?? API ????? %s ????????", name)
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
                logger.info("????? %s ?? Waiting??????????", name)
                await asyncio.sleep(poll_interval)
                continue

            if status_norm in stop_statuses:
                logger.warning("????? %s ??? %s??????", name, status)
                await self.restart_container()
                await asyncio.sleep(poll_interval)
                continue

            logger.info("????? %s ??? %s??????????", name, status or "")
            break

    async def restart_container(self) -> None:
        """?? ACS ???????"""
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.error("??? acs.container_name????????")
            return

        try:
            task = self.container_client.find_instance_by_name(name)
        except Exception as exc:
            logger.error("???? %s ???????: %s", name, exc)
            return

        if not task:
            logger.error("????? %s??????", name)
            return

        task_id = task.get("instanceServiceId") or task.get("id")
        if not task_id:
            logger.error("?? %s ?? instanceServiceId??????", name)
            return

        logger.warning("?????? %s?task id: %s?", name, task_id)
        try:
            resp = self.container_client.restart_task(task_id)
        except Exception as exc:
            logger.error("????????: %s", exc)
            return

        if str(resp.get("code")) == "0":
            logger.info("??????: %s", resp)
            self.state["last_restart"] = dt.datetime.now()
        else:
            logger.error("??????: %s", resp)

    # ------------------------------------------------------------------
    # ???????????
    # ------------------------------------------------------------------

    def _parse_start_time(self, value: Optional[str]) -> Optional[dt.datetime]:
        """?? ACS ??? startTime/createTime ????"""
        if not value:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return dt.datetime.strptime(str(value), fmt)
            except ValueError:
                continue
        return None

    def _parse_timeout_limit(self, value: Optional[str]) -> Optional[dt.timedelta]:
        """?? timeoutLimit??? '360:00:00'?? timedelta?"""
        if not value:
            return None
        parts = str(value).split(":")
        if len(parts) != 3:
            return None
        try:
            hours, minutes, seconds = (int(x) for x in parts)
        except ValueError:
            return None
        return dt.timedelta(hours=hours, minutes=minutes, seconds=seconds)

    async def monitor_container(
        self,
        *,
        pre_shutdown_minutes: int = 10,
        slow_interval: int = 300,
        fast_interval: int = 30,
    ) -> None:
        """????????????????????????????????"""
        acs_cfg = self._acs_cfg(reload=True)
        name = acs_cfg.get("container_name")
        if not name:
            logger.warning("??? acs.container_name????????")
            return

        stop_statuses = {"terminated", "stopped", "stop", "failed"}
        waiting_statuses = {"waiting"}

        while not self._stop_requested:
            interval = slow_interval
            try:
                try:
                    info = self.container_client.get_container_instance_info_by_name(name)
                except Exception as exc:
                    # ?????????? 401??????????????
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

                    # ?? startTime + timeoutLimit ???????????????
                    start_dt = self._parse_start_time(start_time_str)
                    timeout = self._parse_timeout_limit(info.get("timeoutLimit"))
                    now = dt.datetime.now()
                    if start_dt and timeout:
                        try:
                            self.state["timeout_limit"] = info.get("timeoutLimit")
                            next_shutdown = start_dt + timeout
                            self.state["next_shutdown"] = next_shutdown.strftime("%Y-%m-%d %H:%M:%S")
                            remaining = (next_shutdown - now).total_seconds()
                            remaining_sec = int(remaining) if remaining > 0 else 0
                            self.state["remaining_seconds"] = remaining_sec

                            # ??????????????
                            if remaining_sec > 0:
                                days = remaining_sec // 86400
                                hours_left = (remaining_sec % 86400) // 3600
                                mins_left = (remaining_sec % 3600) // 60
                                parts: List[str] = []
                                if days > 0:
                                    parts.append(f"{days} ?")
                                if hours_left > 0:
                                    parts.append(f"{hours_left} ??")
                                if mins_left > 0 or not parts:
                                    parts.append(f"{mins_left} ??")
                                self.state["remaining_time_str"] = " ".join(parts)
                            else:
                                self.state["remaining_time_str"] = "0 ??"

                            # ??????????????????
                            threshold = next_shutdown - dt.timedelta(minutes=pre_shutdown_minutes)
                            if now >= threshold:
                                interval = fast_interval
                            else:
                                interval = slow_interval
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

                    # Waiting ??????????????????????
                    if status_norm in waiting_statuses:
                        logger.info("?? %s ????? Waiting??????????", name)
                        interval = min(interval, fast_interval)

                    if status_norm in stop_statuses:
                        logger.warning("?? %s ??? %s????????", name, status)
                        await self.restart_container()
                        interval = fast_interval
                else:
                    logger.warning("?? %s ??????????????", name)
                    interval = fast_interval
            except Exception as exc:  # pragma: no cover - ??/API ??
                logger.error("??????: %s", exc)
                interval = fast_interval

            await asyncio.sleep(interval)

    # ------------------------------------------------------------------
    # SSH ?????????
    # ------------------------------------------------------------------

    def _forward_ports(self, ssh_cfg: Dict[str, Any]) -> List[int]:
        """???????????????? -L ??????"""
        ports: List[int] = []
        forwards = ssh_cfg.get("forwards") or []
        for spec in forwards:
            local = spec.get("local")
            if local is not None:
                ports.append(int(local))
        return ports

    def _ports_available(self, ports: List[int]) -> bool:
        """???????????????"""
        for p in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("127.0.0.1", p))
                except OSError:
                    logger.error("???? %s ????????????????", p)
                    return False
        return True

    def _kill_ssh_on_ports(self, ports: List[int]) -> None:
        """???????????????? ssh ???"""
        current_user = getpass.getuser()
        targets: List[int] = []
        for conn in psutil.net_connections(kind="inet"):
            if (
                conn.laddr
                and conn.laddr.port in ports
                and conn.status == psutil.CONN_LISTEN
                and conn.pid is not None
            ):
                try:
                    proc = psutil.Process(conn.pid)
                    if "ssh" in proc.name().lower() and proc.username() == current_user:
                        targets.append(proc.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        for pid in targets:
            try:
                proc = psutil.Process(pid)
                logger.warning("????????? ssh ?? pid=%s", pid)
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
        """?????????????????????? fuser?????? sudo??"""
        if not host or not user or not ports:
            return

        cmd: List[str] = ["ssh", "-T"]
        if jump:
            cmd += ["-J", jump]
        if ssh_port:
            cmd += ["-p", str(ssh_port)]
        cmd.append(f"{user}@{host}")
        cmd += ["bash", "-s"]

        plist = " ".join(str(p) for p in ports)
        script_lines = [
            'PREF=""',
            'if command -v sudo >/dev/null 2>&1 && {use_sudo}; then PREF="sudo -n"; fi',
            "for p in {plist}; do",
            "  if command -v fuser >/dev/null 2>&1; then",
            "    $PREF fuser -k $p/tcp || true",
            "  fi",
            "done",
        ]
        script = "\n".join(script_lines).format(
            plist=plist,
            use_sudo="true" if allow_sudo else "false",
        )
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
                logger.debug("????????? %s", res.returncode)
                if err:
                    logger.debug("?????? stderr: %s", err)
            elif out:
                logger.debug("????????: %s", out)
        except Exception as exc:
            logger.info("????????: %s", exc)

    def _remote_cleanup_ports(self, ports: List[int]) -> None:
        """??????????????????????"""
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
                allow_sudo=False,
            )
        if target_ip:
            jump = (
                f"{bastion_user}@{bastion_host}"
                if bastion_host and mode in {"jump", "double"}
                else None
            )
            self._remote_kill_ports_on_host(
                host=target_ip,
                user=target_user,
                ports=ports,
                ssh_port=container_port,
                jump=jump,
                allow_sudo=True,
            )

    def _reverse_specs(self, ssh_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """???????? reverse_forwards(local->remote[,intermediate])?"""
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
            if local is None or remote is None:
                continue
            specs.append(
                {
                    "local": int(local),
                    "remote": int(remote),
                    "mid": int(mid) if mid is not None else None,
                }
            )
        return specs

    async def _ensure_ports_free(
        self,
        ports: List[int],
        retries: int = 3,
        delay: float = 1.0,
    ) -> bool:
        """???????????????/?????????"""
        for attempt in range(retries):
            if self._ports_available(ports):
                return True
            await self.stop_tunnel()
            self._kill_ssh_on_ports(ports)
            self._remote_cleanup_ports(ports)
            if attempt < retries - 1:
                await asyncio.sleep(delay)
        return self._ports_available(ports)

    def build_ssh_command(self, *, reload_config: bool = True) -> List[str]:
        """?? ssh ????? direct / jump / double ?????"""
        ssh_cfg = self._ssh_cfg(reload=reload_config)

        target_ip = self.state.get("container_ip") or ssh_cfg.get("container_ip")
        if not target_ip:
            target_ip = self.resolve_container_ip()
        if not target_ip:
            raise ValueError("?? IP ???????????")

        mode = (ssh_cfg.get("mode") or "jump").lower()
        target_user = ssh_cfg.get("target_user", "root")
        bastion_host = ssh_cfg.get("bastion_host") or ssh_cfg.get("remote_server_ip")
        bastion_user = ssh_cfg.get("bastion_user") or target_user
        ssh_port = ssh_cfg.get("port")
        password_login = ssh_cfg.get("password_login")
        password = ssh_cfg.get("password")
        forwards = ssh_cfg.get("forwards") or []
        local_open_port = ssh_cfg.get("local_open_port")
        container_open_port = ssh_cfg.get("container_open_port")

        if password_login and password:
            logger.info("????????????????????????????")

        def add_port(base: List[str], port_value: Any) -> None:
            if port_value:
                base.extend(["-p", str(port_value)])

        def add_forwards(base: List[str], remote_host: str = "localhost") -> None:
            if not forwards:
                return
            for spec in forwards:
                local = spec.get("local")
                remote = spec.get("remote")
                if local is not None and remote is not None:
                    base.extend(["-L", f"{local}:{remote_host}:{remote}"])

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
                raise ValueError(
                    "double ?????? ssh.bastion_host ? ssh.remote_server_ip?",
                )
            revs = self._reverse_specs(ssh_cfg)
            if any(spec.get("mid") is None for spec in revs):
                raise ValueError(
                    "double ????????? intermediate_port ??? reverse_forwards.intermediate?",
                )

            # ????? -> ???
            outer: List[str] = ["ssh", "-T"] + keepalive
            add_port(outer, ssh_port)
            add_forwards(outer, remote_host="localhost")
            for spec in revs:
                outer.extend(["-R", f"{spec['mid']}:localhost:{spec['local']}"])
            outer.append(f"{bastion_user}@{bastion_host}")

            # ?????? -> ??
            inner: List[str] = ["ssh", "-T", "-N"] + keepalive
            add_port(inner, ssh_cfg.get("container_port") or ssh_port)
            for spec in revs:
                inner.extend(["-R", f"{spec['remote']}:localhost:{spec['mid']}"])
            inner.append(f"{target_user}@{target_ip}")
            outer.append(" ".join(inner))
            return outer

        # direct / jump ??
        cmd: List[str] = ["ssh", "-T", "-N"] + keepalive
        add_port(cmd, ssh_port)
        if mode == "jump":
            if not bastion_host:
                raise ValueError(
                    "jump ?????? ssh.bastion_host ? ssh.remote_server_ip?",
                )
            cmd.extend(["-J", f"{bastion_user}@{bastion_host}"])

        add_forwards(cmd, remote_host="localhost")

        # ??????????????????????? -R
        if local_open_port and container_open_port:
            cmd.extend([
                "-R",
                f"{container_open_port}:localhost:{local_open_port}",
            ])

        cmd.append(f"{target_user}@{target_ip}")
        return cmd

    def build_tunnel_command(self) -> List[str]:
        """??????????? ssh ?????"""
        base = self.build_ssh_command()
        mode = (self._ssh_cfg(reload=False).get("mode") or "jump").lower()
        if mode == "double":
            return base
        # ???????????? ssh -N???????
        return ["ssh", "-o", "ExitOnForwardFailure=yes", "-N"] + base[1:]

    # ------------------------------------------------------------------
    # SSH ??????
    # ------------------------------------------------------------------

    async def start_tunnel(self) -> None:
        """?? SSH ?????????????"""
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
                        logger.error("???? IP ??????: %s", exc)
                    target_ip = (
                        self.state.get("container_ip")
                        or self.resolve_container_ip(force_login=False)
                        or self.resolve_container_ip(force_login=True)
                    )
                    if not target_ip:
                        raise ValueError("?? IP ??????????")

                reverse_specs = self._reverse_specs(ssh_cfg)
                ports = self._forward_ports(ssh_cfg)

                # ???????????????????? ssh ??
                remote_ports = [spec["remote"] for spec in reverse_specs if spec.get("remote")]
                intermediate_ports = [spec["mid"] for spec in reverse_specs if spec.get("mid")]
                if reverse_specs:
                    logger.info(
                        "????????: container=%s, intermediate=%s",
                        remote_ports,
                        intermediate_ports,
                    )
                    self._remote_cleanup_ports(remote_ports + intermediate_ports)
                    await asyncio.sleep(1.0)

                # ??????????????????????? ssh ??
                if ports and not await self._ensure_ports_free(ports):
                    self.state["tunnel_status"] = "error"
                    return

                cmd = self.build_tunnel_command()
            except Exception as exc:
                logger.error("????????: %s", exc)
                self.state["tunnel_status"] = "error"
                return

            logger.info("?? SSH ??: %s", " ".join(cmd))
            proc = await asyncio.create_subprocess_exec(*cmd)
            self._tunnel_process = proc
            self.state["tunnel_status"] = "running"
            self._tunnel_started_once = True

    async def stop_tunnel(self) -> None:
        """?? SSH ????????"""
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
        """?????????????????"""
        await self.stop_tunnel()
        await self.start_tunnel()

    async def maintain_tunnel(self) -> None:
        """?????????????????????????? IP?"""
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
                    logger.info("SSH ???????")
                else:
                    self._tunnel_failure_count += 1
                    logger.warning(
                        "SSH ????? %s?????????????: %s??",
                        rc,
                        self._tunnel_failure_count,
                    )
                    if self._tunnel_failure_count >= 3:
                        name = self._acs_cfg(reload=True).get("container_name")
                        logger.warning(
                            "SSH ?????? >=3 ?????? API ???? IP???: %s??",
                            name,
                        )
                        self.resolve_container_ip(force_login=True)
                        self._tunnel_failure_count = 0
            except Exception as exc:  # pragma: no cover - ?????
                logger.error("SSH ????: %s", exc)
            finally:
                await self.stop_tunnel()
            await asyncio.sleep(3)

    async def shutdown(self) -> None:
        """??????????? SSH ???"""
        self._stop_requested = True
        await self.stop_tunnel()

    # ------------------------------------------------------------------
    # ????
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """?????????? Web UI ????"""
        return dict(self.state)
