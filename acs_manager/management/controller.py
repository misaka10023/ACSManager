# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import datetime as dt
import getpass
import logging
import os
import re
import shlex
import subprocess
from asyncio.subprocess import Process
from typing import Any, Dict, List, Optional

import psutil

from acs_manager.capture.sniffer import PacketSniffer
from acs_manager.config.store import ConfigStore
from acs_manager.container.client import ContainerClient
from acs_manager.config.state_store import RuntimeStateStore

logger = logging.getLogger(__name__)


class ContainerManager:
    """处理 ACS 容器生命周期、IP 跟踪与 SSH 隧道维护。"""

    PLACEHOLDER_CONTAINER_NAMES = {"default", "placeholder", "none"}

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
            "ip_source": None,
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
        self._tunnel_config_event = asyncio.Event()
        self._task_exec_lock = asyncio.Lock()
        self._ssh_ask_warned = False

    @staticmethod
    def _normalize_container_name(name: Optional[str]) -> str:
        return str(name or "").strip().lower()

    def is_placeholder_container_name(self, name: Optional[str] = None) -> bool:
        if name is None:
            name = self._acs_cfg(reload=False).get("container_name")
        normalized = self._normalize_container_name(name)
        return normalized == "" or normalized in self.PLACEHOLDER_CONTAINER_NAMES

    def configured_container_name(self, *, reload: bool = False) -> Optional[str]:
        name = self._acs_cfg(reload=reload).get("container_name")
        if self.is_placeholder_container_name(name):
            return None
        return str(name).strip()

    @staticmethod
    def _slugify_task_id(value: Optional[str], fallback: str) -> str:
        normalized = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(value or "").strip().lower()).strip("-_")
        return normalized or fallback

    def _task_cfgs(self, *, reload: bool = False) -> List[Dict[str, Any]]:
        try:
            root = self.store.read(reload=reload)
        except Exception:
            return []
        tasks = root.get("tasks", []) if isinstance(root, dict) else []
        if not isinstance(tasks, list):
            return []

        normalized: List[Dict[str, Any]] = []
        for idx, raw in enumerate(tasks):
            if not isinstance(raw, dict):
                continue
            fallback_id = f"task-{idx + 1}"
            title = str(raw.get("title") or raw.get("name") or raw.get("id") or fallback_id).strip()
            task_id = self._slugify_task_id(raw.get("id") or title, fallback_id)
            trigger = str(raw.get("trigger") or "manual").strip().lower()
            if trigger not in {"manual", "auto_on_start"}:
                trigger = "manual"
            mode = str(raw.get("mode") or "once").strip().lower()
            if mode not in {"once", "ensure_running"}:
                mode = "once"
            runner_raw = raw.get("runner", {}) if isinstance(raw.get("runner"), dict) else {}
            runner_type = str(runner_raw.get("type") or ("screen" if mode == "ensure_running" else "nohup")).strip().lower()
            if runner_type == "tmux":
                runner_type = "screen"
            if runner_type not in {"screen", "nohup", "shell"}:
                runner_type = "nohup"
            session_name = str(runner_raw.get("session") or task_id).strip() or task_id
            normalized.append(
                {
                    "id": task_id,
                    "title": title or task_id,
                    "enabled": bool(raw.get("enabled", True)),
                    "trigger": trigger,
                    "mode": mode,
                    "workdir": str(raw.get("workdir") or "").strip(),
                    "command": str(raw.get("command") or "").strip(),
                    "log_file": str(raw.get("log_file") or "").strip(),
                    "runner": {
                        "type": runner_type,
                        "session": session_name,
                    },
                }
            )
        return normalized

    def _task_config(self, task_id: str, *, reload: bool = False) -> Optional[Dict[str, Any]]:
        target = str(task_id or "").strip()
        for task in self._task_cfgs(reload=reload):
            if task.get("id") == target:
                return task
        return None

    def _task_state(self, task_id: str) -> Dict[str, Any]:
        if not self.state_store:
            return {}
        try:
            return self.state_store.read_task(self.container_id, task_id)
        except Exception:
            return {}

    def _persist_task_state(self, task_id: str, changes: Dict[str, Any]) -> Dict[str, Any]:
        if not self.state_store:
            return {}
        try:
            return self.state_store.update_task(self.container_id, task_id, changes)
        except Exception as exc:
            logger.warning("Failed to persist task state for %s/%s: %s", self.container_id, task_id, exc)
            return {}

    def list_task_summaries(self, *, reload: bool = False) -> List[Dict[str, Any]]:
        summaries: List[Dict[str, Any]] = []
        for task in self._task_cfgs(reload=reload):
            state = self._task_state(task["id"])
            summaries.append(
                {
                    "id": task["id"],
                    "title": task["title"],
                    "enabled": task["enabled"],
                    "trigger": task["trigger"],
                    "mode": task["mode"],
                    "workdir": task["workdir"],
                    "log_file": task["log_file"],
                    "runner_type": task["runner"]["type"],
                    "runner_session": task["runner"]["session"],
                    "last_status": state.get("last_status") or "idle",
                    "last_message": state.get("last_message") or "",
                    "last_run_at": state.get("last_run_at"),
                    "last_reason": state.get("last_reason"),
                    "last_returncode": state.get("last_returncode"),
                    "last_pid": state.get("last_pid"),
                }
            )
        return summaries

    async def handle_new_ip(self, ip: str, *, source: Optional[str] = None) -> None:
        """捕获到新的容器 IP 时更新状态，若隧道已启动则重启隧道。"""
        old_ip = self.state.get("container_ip")
        self.state["last_seen"] = dt.datetime.now()
        if source:
            self.state["ip_source"] = source

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
                await asyncio.to_thread(self.store.update, {"ssh": updated_ssh})
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
        name = self.configured_container_name(reload=True)
        if not name:
            logger.warning("acs.container_name not configured or placeholder; cannot auto-resolve IP.")
            return None
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
            self.state["ip_source"] = info.get("ipSource") or "api"
            if info.get("status"):
                self.state["container_status"] = info.get("status")
            if info.get("startTime"):
                self.state["container_start_time"] = info.get("startTime")
            if info.get("remainingTime"):
                self.state["remaining_time_str"] = info.get("remainingTime")
            logger.info("Resolved container IP via API: %s", ip)
            return ip
        logger.warning("Could not resolve container %s IP from API.", name)
        return None

    async def ingest_capture_event(self, payload: Dict[str, Any]) -> Optional[str]:
        """Extract an IP from a captured ACS payload and apply it to this container."""
        ip = PacketSniffer.extract_ip(payload)
        if not ip:
            logger.warning("No IP found in captured payload for container %s.", self.container_id)
            return None
        await self.handle_new_ip(ip, source="capture")
        return ip
    async def ensure_running(self) -> None:
        """检测到容器停止时触发重启。"""
        await self.restart_container()

    @staticmethod
    def _restart_response_not_found(resp: Optional[Dict[str, Any]]) -> bool:
        if not isinstance(resp, dict):
            return False
        code = str(resp.get("code") or "").strip()
        msg = str(resp.get("msg") or "").strip()
        return code == "816822" or "任务不存在" in msg

    @staticmethod
    def _collect_restart_ids(*records: Optional[Dict[str, Any]]) -> List[str]:
        ids: List[str] = []
        seen: set[str] = set()
        for record in records:
            if not isinstance(record, dict):
                continue
            for key in ("instanceServiceId", "taskId", "id"):
                value = str(record.get(key) or "").strip()
                if value and value not in seen:
                    ids.append(value)
                    seen.add(value)
        return ids

    def _load_recreate_detail(self, task: Dict[str, Any], service_type: str = "container") -> Optional[Dict[str, Any]]:
        attempts: List[tuple[str, Any, str]] = []
        seen: set[tuple[str, str]] = set()

        def add_attempt(label: str, fn: Any, value: Any) -> None:
            task_id = str(value or "").strip()
            if not task_id:
                return
            key = (label, task_id)
            if key in seen:
                return
            seen.add(key)
            attempts.append((label, fn, task_id))

        if service_type == "notebook":
            add_attempt("notebook detail", self.container_client.get_notebook_record_detail, task.get("id"))
        else:
            add_attempt("instance detail", self.container_client.get_instance_detail, task.get("instanceServiceId"))
            add_attempt("instance detail", self.container_client.get_instance_detail, task.get("id"))

        last_exc: Optional[Exception] = None
        for label, fn, task_id in attempts:
            try:
                detail = fn(task_id)
            except Exception as exc:
                last_exc = exc
                continue
            data = detail.get("data") if isinstance(detail, dict) else None
            if data is None and isinstance(detail, dict):
                data = detail
            if isinstance(data, dict) and data:
                return data
            logger.warning("Unexpected %s format when recreating task %s", label, task_id)

        if last_exc:
            logger.error("Failed to fetch task detail for recreate: %s", last_exc)
        if service_type == "notebook" and task:
            return dict(task)
        return None

    def _recreate_container_task(self, base_name: str, task: Dict[str, Any]) -> bool:
        """创建新的任务实例，名称遵循 baseName_counter_timestamp。"""
        task_id = task.get("instanceServiceId") or task.get("taskId") or task.get("id")
        if not task_id:
            logger.error("Cannot recreate task without instanceServiceId/taskId/id.")
            return False

        restart_cfg = self._restart_cfg(reload=False)
        new_count = restart_cfg.get("create_count", 0) + 1
        timestamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
        new_name = f"{base_name}_{new_count}_{timestamp}"

        data = self._load_recreate_detail(task, "container")
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
                # Persist the new ACS task name for future IP resolution and tunnel restarts.
                self.store.update({"acs": {"container_name": new_name}})
            except Exception as exc:  # pragma: no cover - IO errors
                logger.warning("Failed to persist new container_name %s: %s", new_name, exc)
            return True

        logger.error("Create new task failed: %s", resp)
        return False

    def _recreate_notebook_task(self, base_name: str, task: Dict[str, Any]) -> bool:
        """Create a new Notebook task with the same resource shape."""
        task_id = task.get("id")
        if not task_id:
            logger.error("Cannot recreate notebook task without notebook record id.")
            return False

        restart_cfg = self._restart_cfg(reload=False)
        new_count = restart_cfg.get("create_count", 0) + 1
        timestamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
        new_name = f"{base_name}_{new_count}_{timestamp}"

        data = self._load_recreate_detail(task, "notebook")
        if not isinstance(data, dict):
            logger.error("Unexpected detail format when recreating notebook task %s", task_id)
            return False

        payload: Dict[str, Any] = {}
        allowed_keys = [
            "description",
            "type",
            "acceleratorType",
            "imagePath",
            "imageVersion",
            "resourceSpec",
            "resourceGroup",
            "cpuNumber",
            "ramSize",
            "gpuNumber",
            "maxWallTime",
            "timeoutLimit",
            "useStartScript",
        ]
        for key in allowed_keys:
            if key in data and data[key] is not None:
                payload[key] = data[key]

        payload["notebookName"] = new_name
        payload.setdefault("description", data.get("description", ""))
        payload.setdefault("type", data.get("type") or data.get("taskType") or "jupyter")
        payload.setdefault("acceleratorType", data.get("acceleratorType") or "gpu")
        payload.setdefault("imagePath", data.get("imagePath") or "")
        payload.setdefault("imageVersion", data.get("imageVersion") or data.get("version") or "")
        payload.setdefault("resourceSpec", data.get("resourceSpec") or "")
        payload.setdefault("resourceGroup", data.get("resourceGroup") or "default")
        payload.setdefault("cpuNumber", data.get("cpuNumber") or 1)
        payload.setdefault("ramSize", data.get("ramSize") or 1024)
        payload.setdefault("gpuNumber", data.get("gpuNumber") or 0)
        payload.setdefault("maxWallTime", data.get("maxWallTime") or "unlimited")
        if not payload.get("timeoutLimit") and payload.get("maxWallTime") not in {None, "", "unlimited"}:
            payload["timeoutLimit"] = payload["maxWallTime"]
        if payload.get("timeoutLimit") == "unlimited":
            payload["timeoutLimit"] = ""
        payload["autoTerminated"] = 1 if payload.get("timeoutLimit") else 0

        try:
            resp = self.container_client.create_notebook_task(payload)
        except Exception as exc:
            logger.error("Create new notebook task failed: %s", exc)
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
            logger.info("Created new notebook task %s from %s: %s", new_name, base_name, resp)
            try:
                self.store.update({"acs": {"container_name": new_name}})
            except Exception as exc:  # pragma: no cover - IO errors
                logger.warning("Failed to persist new notebook container_name %s: %s", new_name, exc)
            return True

        logger.error("Create new notebook task failed: %s", resp)
        return False

    async def restart_container(
        self,
        info: Optional[Dict[str, Any]] = None,
        *,
        name_hint: Optional[str] = None,
    ) -> str:
        """调用 ACS 重启接口。"""
        name = str(name_hint or self.configured_container_name(reload=True) or "").strip()
        if not name:
            logger.error("acs.container_name not configured or placeholder; cannot restart.")
            return "error"

        restart_cfg = self._restart_cfg(reload=True)
        if restart_cfg.get("strategy") == "none":
            logger.info("Restart strategy is none; skip restarting or recreating container %s.", name)
            return "skipped"

        service_type = str(self._acs_cfg(reload=True).get("service_type") or "container").strip().lower()
        try:
            task = await asyncio.to_thread(self.container_client.find_instance_by_name, name)
        except Exception as exc:
            logger.error("Failed to query container %s; cannot restart: %s", name, exc)
            task = None

        restart_target = task or info
        recreate_target = task or info

        if restart_cfg.get("strategy") == "recreate":
            base_name = self.display_name or name
            logger.warning("Recreate strategy enabled; creating new task for %s (base name: %s)", name, base_name)
            try:
                if service_type == "notebook":
                    created = await asyncio.to_thread(self._recreate_notebook_task, base_name, recreate_target or {})
                else:
                    created = await asyncio.to_thread(self._recreate_container_task, base_name, recreate_target or {})
            except Exception as exc:
                logger.error("Recreate task call failed: %s", exc, exc_info=True)
                return "error"
            if created:
                return "recreated"
            logger.error("Recreate task failed; not falling back to restart original task.")
            return "error"

        if service_type == "notebook":
            if not isinstance(restart_target, dict):
                logger.error("Notebook %s not found; cannot restart.", name)
                return "error"
            notebook_id = str(restart_target.get("id") or "").strip()
            if not notebook_id:
                logger.error("Notebook %s is missing notebook record id; cannot restart.", name)
                return "error"
            timeout_limit = restart_target.get("timeoutLimit")
            auto_terminated = restart_target.get("autoTerminated")
            if auto_terminated is None:
                auto_terminated = 1 if timeout_limit and timeout_limit != "unlimited" else 0
            logger.warning("Attempting to restart notebook %s (notebook id: %s)", name, notebook_id)
            try:
                resp = await asyncio.to_thread(
                    self.container_client.restart_notebook_task,
                    notebook_id,
                    auto_terminated=auto_terminated,
                    timeout_limit=timeout_limit,
                )
            except Exception as exc:
                logger.error("Notebook restart API call failed: %s", exc)
                return "error"
            if str(resp.get("code")) == "0":
                logger.info("Notebook restart request accepted: %s", resp)
                self.state["last_restart"] = dt.datetime.now()
                return "restarted"
            logger.error("Notebook restart request failed: %s", resp)
            return "error"

        restart_ids = self._collect_restart_ids(restart_target, info, task)
        last_resp: Optional[Dict[str, Any]] = None
        if restart_target and restart_ids:
            for task_id in restart_ids:
                logger.warning("Attempting to restart container %s (task id: %s)", name, task_id)
                try:
                    resp = await asyncio.to_thread(self.container_client.restart_task, task_id)
                except Exception as exc:
                    logger.error("Restart API call failed: %s", exc)
                    return "error"
                if str(resp.get("code")) == "0":
                    logger.info("Restart request accepted: %s", resp)
                    self.state["last_restart"] = dt.datetime.now()
                    return "restarted"
                last_resp = resp
                if not self._restart_response_not_found(resp):
                    logger.error("Restart request failed: %s", resp)
                    return "error"

        if last_resp is not None:
            logger.error("Restart request failed: %s", last_resp)
        else:
            logger.error("Container %s not found or missing usable restart identifiers; cannot restart.", name)
        return "error"

    @staticmethod
    def _trim_task_output(value: str, limit: int = 1200) -> str:
        text = str(value or "").strip()
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    def _task_shell_body(self, task: Dict[str, Any]) -> str:
        command = str(task.get("command") or "").strip()
        if not command:
            raise ValueError("Task command is empty.")
        workdir = str(task.get("workdir") or "").strip()
        if workdir:
            return f"cd {shlex.quote(workdir)} && {command}"
        return command

    def _ssh_keepalive_options(self, ssh_cfg: Dict[str, Any]) -> List[str]:
        """Build the standard SSH keepalive option list.

        Honors ``ssh.strict_host_key_checking`` (yes|no|accept-new|ask) and
        ``ssh.user_known_hosts_file`` overrides. Policy:

        - If ``user_known_hosts_file`` is set explicitly, point both
          UserKnownHostsFile and GlobalKnownHostsFile at it regardless of mode.
        - Else if ``strict_host_key_checking`` is ``no``, route to the OS null
          sink (caller explicitly opted out of host-key checking).
        - Else (``yes`` / ``accept-new`` / ``ask``) omit the known-hosts
          overrides so OpenSSH falls back to ``~/.ssh/known_hosts``; this
          preserves trust-on-first-use for ``accept-new``.
        """
        allowed_modes = {"yes", "no", "accept-new", "ask"}
        strict_mode = str(ssh_cfg.get("strict_host_key_checking") or "accept-new").strip().lower()
        if strict_mode not in allowed_modes:
            strict_mode = "accept-new"

        if strict_mode == "ask" and not self._ssh_ask_warned:
            logger.warning(
                "ssh.strict_host_key_checking='ask' is not viable without a TTY; "
                "tunnel may exit. Consider 'accept-new'."
            )
            self._ssh_ask_warned = True

        os_default_null = "NUL" if os.name == "nt" else "/dev/null"
        configured_known_hosts = ssh_cfg.get("user_known_hosts_file")
        known_hosts: Optional[str]
        if configured_known_hosts:
            known_hosts = str(configured_known_hosts)
        elif strict_mode == "no":
            known_hosts = os_default_null
        else:
            known_hosts = None

        options: List[str] = [
            "-o",
            "ServerAliveInterval=60",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            f"StrictHostKeyChecking={strict_mode}",
            # All SSH invocations run without a TTY (asyncio.create_subprocess_exec
            # / subprocess.run). BatchMode=yes prevents host-key or password
            # prompts from blocking until timeout. accept-new still adds new
            # keys silently under BatchMode=yes; only key conflicts will fail.
            "-o",
            "BatchMode=yes",
        ]
        if known_hosts is not None:
            options.extend([
                "-o",
                f"UserKnownHostsFile={known_hosts}",
                "-o",
                f"GlobalKnownHostsFile={known_hosts}",
            ])
        return options

    def _build_ssh_exec_command(self, remote_command: str, *, reload_config: bool = True) -> List[str]:
        ssh_cfg = self._ssh_cfg(reload=reload_config)
        target_ip = self.state.get("container_ip") or ssh_cfg.get("container_ip")
        if not target_ip:
            target_ip = self.resolve_container_ip()
        if not target_ip:
            raise ValueError("Container IP unknown; cannot execute task.")

        mode = (ssh_cfg.get("mode") or "jump").lower()
        target_user = ssh_cfg.get("target_user", "root")
        bastion_host = ssh_cfg.get("bastion_host")
        bastion_user = ssh_cfg.get("bastion_user") or target_user
        ssh_port = ssh_cfg.get("port")
        container_port = ssh_cfg.get("container_port") or ssh_port

        keepalive = self._ssh_keepalive_options(ssh_cfg)

        def add_port(base: List[str], port_value: Any) -> None:
            if port_value:
                base.extend(["-p", str(port_value)])

        if mode == "double":
            if not bastion_host:
                raise ValueError("double mode requires ssh.bastion_host")
            outer: List[str] = ["ssh", "-T"] + keepalive
            add_port(outer, ssh_port)
            outer.append(f"{bastion_user}@{bastion_host}")

            inner: List[str] = ["ssh", "-T"] + keepalive
            add_port(inner, container_port)
            inner.append(f"{target_user}@{target_ip}")
            inner.append(remote_command)
            outer.append(" ".join(shlex.quote(part) for part in inner))
            return outer

        cmd: List[str] = ["ssh", "-T"] + keepalive
        add_port(cmd, ssh_port)
        if mode == "jump":
            if not bastion_host:
                raise ValueError("jump mode requires ssh.bastion_host")
            cmd.extend(["-J", f"{bastion_user}@{bastion_host}"])
        cmd.append(f"{target_user}@{target_ip}")
        cmd.append(remote_command)
        return cmd

    def _run_remote_shell(
        self,
        remote_command: str,
        *,
        timeout: int = 60,
        reload_config: bool = True,
        allowed_returncodes: Optional[set[int]] = None,
    ) -> Dict[str, Any]:
        cmd = self._build_ssh_exec_command(remote_command, reload_config=reload_config)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout = self._trim_task_output(proc.stdout or "")
        stderr = self._trim_task_output(proc.stderr or "")
        ok_codes = allowed_returncodes or {0}
        return {
            "ok": proc.returncode in ok_codes,
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "command": cmd,
        }

    def _task_session_exists(self, session_name: str) -> bool:
        probe = self._run_remote_shell(
            f"screen -ls | grep -Fq {shlex.quote('.' + session_name)}",
            timeout=20,
            reload_config=False,
            allowed_returncodes={0, 1},
        )
        return probe.get("returncode") == 0

    def _task_screen_marker_path(self, task_id: str) -> str:
        container_key = self._slugify_task_id(self.container_id, "container")
        task_key = self._slugify_task_id(task_id, "task")
        return f"/tmp/acs-manager-{container_key}-{task_key}.running"

    def _task_screen_is_running(self, session_name: str, marker_path: str) -> bool:
        probe = self._run_remote_shell(
            f"screen -ls | grep -Fq {shlex.quote('.' + session_name)} && [ -f {shlex.quote(marker_path)} ]",
            timeout=20,
            reload_config=False,
            allowed_returncodes={0, 1},
        )
        return probe.get("returncode") == 0

    def _reset_task_screen_session(self, session_name: str, marker_path: str) -> None:
        self._run_remote_shell(
            (
                f"screen -S {shlex.quote(session_name)} -X quit >/dev/null 2>&1 || true; "
                f"rm -f {shlex.quote(marker_path)} >/dev/null 2>&1 || true"
            ),
            timeout=20,
            reload_config=False,
            allowed_returncodes={0},
        )

    def _execute_task_sync(self, task: Dict[str, Any], *, force: bool = False, reason: str = "manual") -> Dict[str, Any]:
        task_id = task["id"]
        runner = task["runner"]["type"]
        session_name = task["runner"]["session"]
        now = dt.datetime.now().isoformat()
        self._persist_task_state(
            task_id,
            {
                "last_status": "running",
                "last_reason": reason,
                "last_run_at": now,
                "last_message": "Task is starting.",
            },
        )

        shell_body = self._task_shell_body(task)
        log_file = str(task.get("log_file") or "").strip()

        if runner == "screen":
            marker_path = self._task_screen_marker_path(task_id)
            if force:
                self._reset_task_screen_session(session_name, marker_path)
            elif self._task_screen_is_running(session_name, marker_path):
                result = {
                    "success": True,
                    "status": "already_running",
                    "message": f"Task {task['title']} is already running.",
                }
                self._persist_task_state(
                    task_id,
                    {
                        "last_status": "already_running",
                        "last_reason": reason,
                        "last_run_at": now,
                        "last_message": result["message"],
                    },
                )
                return result
            elif self._task_session_exists(session_name):
                # Keep an attachable shell after the managed command exits, but
                # reset any leftover shell before starting a new managed run.
                self._reset_task_screen_session(session_name, marker_path)

            launch = shell_body
            if log_file:
                launch = f"{launch} >> {shlex.quote(log_file)} 2>&1"
            marker_cmd = shlex.quote(marker_path)
            wrapped_launch = (
                f"touch {marker_cmd}; "
                f"trap 'rm -f {marker_cmd}' EXIT; "
                f"{launch}; "
                f"status=$?; "
                f"rm -f {marker_cmd}; "
                f"printf '\\n[acs-manager] task exited with code %s\\n' \"$status\"; "
                f"exec bash -i"
            )
            remote_command = f"screen -dmS {shlex.quote(session_name)} bash -lc {shlex.quote(wrapped_launch)}"
            outcome = self._run_remote_shell(remote_command, timeout=30, reload_config=False)
            success = bool(outcome.get("ok"))
            message = f"Task {task['title']} started in screen session {session_name}." if success else (
                outcome.get("stderr") or outcome.get("stdout") or f"Failed to start task {task['title']}."
            )
            self._persist_task_state(
                task_id,
                {
                    "last_status": "started" if success else "failed",
                    "last_reason": reason,
                    "last_run_at": now,
                    "last_message": self._trim_task_output(message),
                    "last_returncode": outcome.get("returncode"),
                },
            )
            return {
                "success": success,
                "status": "started" if success else "failed",
                "message": self._trim_task_output(message),
                "returncode": outcome.get("returncode"),
            }

        if runner == "nohup":
            launch = f"nohup bash -lc {shlex.quote(shell_body)}"
            if log_file:
                launch = f"{launch} >> {shlex.quote(log_file)} 2>&1"
            launch = f"{launch} & echo $!"
            outcome = self._run_remote_shell(launch, timeout=30, reload_config=False)
            success = bool(outcome.get("ok"))
            pid = None
            if success:
                for line in reversed((outcome.get("stdout") or "").splitlines()):
                    if line.strip().isdigit():
                        pid = int(line.strip())
                        break
            message = f"Task {task['title']} started in background." if success else (
                outcome.get("stderr") or outcome.get("stdout") or f"Failed to start task {task['title']}."
            )
            self._persist_task_state(
                task_id,
                {
                    "last_status": "started" if success else "failed",
                    "last_reason": reason,
                    "last_run_at": now,
                    "last_message": self._trim_task_output(message),
                    "last_returncode": outcome.get("returncode"),
                    "last_pid": pid,
                },
            )
            return {
                "success": success,
                "status": "started" if success else "failed",
                "message": self._trim_task_output(message),
                "returncode": outcome.get("returncode"),
                "pid": pid,
            }

        outcome = self._run_remote_shell(f"bash -lc {shlex.quote(shell_body)}", timeout=3600, reload_config=False)
        success = bool(outcome.get("ok"))
        message = f"Task {task['title']} completed." if success else (
            outcome.get("stderr") or outcome.get("stdout") or f"Task {task['title']} failed."
        )
        self._persist_task_state(
            task_id,
            {
                "last_status": "completed" if success else "failed",
                "last_reason": reason,
                "last_run_at": now,
                "last_message": self._trim_task_output(message),
                "last_returncode": outcome.get("returncode"),
            },
        )
        return {
            "success": success,
            "status": "completed" if success else "failed",
            "message": self._trim_task_output(message),
            "returncode": outcome.get("returncode"),
            "stdout": outcome.get("stdout"),
            "stderr": outcome.get("stderr"),
        }

    async def execute_task(self, task_id: str, *, force: bool = False, reason: str = "manual") -> Dict[str, Any]:
        task = self._task_config(task_id, reload=True)
        if not task:
            raise ValueError(f"Task {task_id} not found")
        if not task.get("enabled", True):
            raise ValueError(f"Task {task['title']} is disabled")
        async with self._task_exec_lock:
            return await asyncio.to_thread(self._execute_task_sync, task, force=force, reason=reason)

    async def _maybe_run_auto_tasks(self, info: Dict[str, Any]) -> None:
        marker = str(
            info.get("startTime")
            or info.get("createTime")
            or self.state.get("container_ip")
            or ""
        ).strip()
        if not marker:
            return
        for task in self._task_cfgs(reload=True):
            if not task.get("enabled", True) or task.get("trigger") != "auto_on_start":
                continue
            state = self._task_state(task["id"])
            if state.get("last_auto_marker") == marker:
                continue
            try:
                result = await self.execute_task(task["id"], force=False, reason="auto_on_start")
            except Exception as exc:
                logger.error("Auto task %s failed for %s: %s", task["id"], self.container_id, exc)
                continue
            if result.get("success"):
                self._persist_task_state(
                    task["id"],
                    {
                        "last_auto_marker": marker,
                        "auto_triggered_at": dt.datetime.now().isoformat(),
                    },
                )

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

    def _fetch_info_sync(self, name: str) -> Optional[Dict[str, Any]]:
        """Synchronous helper: fetch container info, retrying once on 401.

        Designed to be invoked via :func:`asyncio.to_thread` so that the
        underlying :mod:`requests` calls do not block the event loop.
        """
        try:
            return self.container_client.get_container_instance_info_by_name(name)
        except Exception as exc:
            response = getattr(exc, "response", None)
            status_code = getattr(response, "status_code", None) if response is not None else None
            if status_code == 401:
                self.container_client.login()
                return self.container_client.get_container_instance_info_by_name(name)
            raise

    async def monitor_container(self, *, pre_shutdown_minutes: int = 10, slow_interval: int = 300, fast_interval: int = 30) -> None:
        """周期检查容器状态，接近超时时加快轮询，停止则重启。"""
        while not self._stop_requested:
            interval = slow_interval
            name = self.configured_container_name(reload=True)
            if not name:
                logger.warning("acs.container_name not configured or placeholder; monitor loop exits.")
                return
            try:
                info = await asyncio.to_thread(self._fetch_info_sync, name)
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

                    if status_norm == "running":
                        await self._maybe_run_auto_tasks(info)

                    if status_norm in stop_statuses:
                        result = await self.restart_container(info=info, name_hint=name)
                        if result == "skipped":
                            logger.info("Container %s status is %s; restart strategy is none, skip restart.", name, status)
                        else:
                            logger.warning("Container %s status is %s; restart result=%s.", name, status, result)
                        interval = fast_interval
                else:
                    logger.warning("Container %s not found; will retry soon.", name)
                    interval = fast_interval
            except Exception as exc:  # pragma: no cover - network/API errors
                logger.error("Monitor loop error for %s: %s", self.container_id, exc, exc_info=True)
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

        def dynamic_remote_arg(spec: Dict[str, Any], port_key: str = "remote") -> str:
            bind = str(spec.get("bind") or "").strip()
            port = spec.get(port_key)
            return f"{bind}:{port}" if bind else str(port)

        def remote_tcp_arg(spec: Dict[str, Any], remote_key: str, host: str, host_port_key: str) -> str:
            bind = str(spec.get("bind") or "").strip()
            remote = spec.get(remote_key)
            host_port = spec.get(host_port_key)
            suffix = f"{remote}:{host}:{host_port}"
            return f"{bind}:{suffix}" if bind else suffix

        keepalive = self._ssh_keepalive_options(ssh_cfg)

        if mode == "double":
            if not bastion_host:
                raise ValueError("double mode requires ssh.bastion_host or ssh.remote_server_ip")
            revs = self._reverse_specs(ssh_cfg)
            dynamic_revs = self._remote_dynamic_specs(ssh_cfg)
            if revs and any(spec.get("mid") is None for spec in revs):
                raise ValueError("double mode reverse forwarding needs mid (intermediate port) in reverse_forwards")
            if dynamic_revs and any(spec.get("mid") is None for spec in dynamic_revs):
                raise ValueError("double mode remote dynamic forwarding needs mid (intermediate port) in remote_dynamic_forwards")

            outer: List[str] = ["ssh", "-T"] + keepalive
            add_port(outer, ssh_port)
            add_forwards(outer)
            for spec in revs:
                outer.extend(["-R", f"{spec['mid']}:localhost:{spec['local']}"])
            for spec in dynamic_revs:
                outer.extend(["-R", dynamic_remote_arg(spec, "mid")])
            outer.append(f"{bastion_user}@{bastion_host}")
            inner: List[str] = ["ssh", "-T", "-N"] + keepalive
            add_port(inner, ssh_cfg.get("container_port") or ssh_port)
            for spec in revs:
                inner.extend(["-R", f"{spec['remote']}:localhost:{spec['mid']}"])
            for spec in dynamic_revs:
                inner.extend(["-R", remote_tcp_arg(spec, "remote", "localhost", "mid")])
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
            for spec in self._remote_dynamic_specs(ssh_cfg):
                cmd.extend(["-R", dynamic_remote_arg(spec)])
            cmd.append(f"{target_user}@{target_ip}")

        if password_login and password:
            logger.info("Password login enabled; ensure automation handles password input safely.")
        return cmd

    def build_tunnel_command(self) -> List[str]:
        """生成带端口转发的 SSH 隧道命令。

        ``build_ssh_command`` already produces a tunnel-ready command
        (``ssh -T -N`` + keepalive options including ``ExitOnForwardFailure=yes``)
        for both ``direct`` / ``jump`` and ``double`` modes, so no extra prefix
        is needed here.
        """
        return self.build_ssh_command()

    def _has_tunnel_forwards(self, ssh_cfg: Dict[str, Any]) -> bool:
        """Return true only when an SSH tunnel has explicit forwarding work."""
        if self._forward_ports(ssh_cfg):
            return True
        if self._reverse_specs(ssh_cfg):
            return True
        if self._remote_dynamic_specs(ssh_cfg):
            return True
        return False

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
        # Inherit BatchMode=yes / StrictHostKeyChecking from the same keepalive
        # policy used elsewhere so a brand-new container IP cannot stall the
        # cleanup on a host-authenticity prompt until the 8s timeout.
        keepalive = self._ssh_keepalive_options(self._ssh_cfg(reload=False))
        cmd = ["ssh", "-T", *keepalive]
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

    def _remote_dynamic_specs(self, ssh_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse remote dynamic SOCKS specs for OpenSSH -R [bind:]port."""
        revs = ssh_cfg.get("remote_dynamic_forwards") or []
        specs: List[Dict[str, Any]] = []

        def _parse_bind_port(value: str) -> Optional[Dict[str, Any]]:
            raw = value.strip()
            if not raw:
                return None
            parts = raw.split(":")
            if len(parts) == 1:
                return {"bind": "127.0.0.1", "remote": int(parts[0]), "mid": None}
            if len(parts) == 2:
                first, second = parts
                if first.isdigit():
                    return {"bind": "127.0.0.1", "remote": int(first), "mid": int(second)}
                return {"bind": first, "remote": int(second), "mid": None}
            if len(parts) == 3:
                bind, remote, mid = parts
                return {"bind": bind, "remote": int(remote), "mid": int(mid)}
            return None

        def _parse(item: Any) -> Optional[Dict[str, Any]]:
            if isinstance(item, int):
                return {"bind": "127.0.0.1", "remote": int(item), "mid": None}
            if isinstance(item, str):
                return _parse_bind_port(item)
            if isinstance(item, dict):
                remote = item.get("remote", item.get("port"))
                mid = item.get("intermediate") or item.get("mid")
                if remote is None:
                    return None
                bind = str(item.get("bind", "127.0.0.1") or "").strip() or "127.0.0.1"
                return {
                    "bind": bind,
                    "remote": int(remote),
                    "mid": int(mid) if mid else None,
                }
            return None

        for item in revs:
            try:
                parsed = _parse(item)
            except (TypeError, ValueError):
                parsed = None
            if parsed:
                specs.append(parsed)
        return specs

    async def _ensure_ports_free(self, ports: List[int], retries: int = 3, delay: float = 1.0) -> bool:
        """隧道重连前多次尝试释放端口。"""
        for attempt in range(retries):
            if await asyncio.to_thread(self._ports_available, ports):
                return True
            await self._stop_tunnel_locked()
            await asyncio.to_thread(self._kill_ssh_on_ports, ports)
            await asyncio.to_thread(self._remote_cleanup_ports, ports)
            if attempt < retries - 1:
                await asyncio.sleep(delay)
        return await asyncio.to_thread(self._ports_available, ports)

    async def start_tunnel(self) -> None:
        """启动 SSH 隧道（若未运行）。"""
        async with self._proc_lock:
            if self._tunnel_process and self._tunnel_process.returncode is None:
                return
            try:
                ssh_cfg = self._ssh_cfg(reload=True)
                if not self._has_tunnel_forwards(ssh_cfg):
                    self.state["tunnel_status"] = "disabled"
                    logger.info("No SSH forwards configured for container %s; skip tunnel start.", self.container_id)
                    return
                target_ip = self.state.get("container_ip") or ssh_cfg.get("container_ip")
                if not target_ip:
                    try:
                        await asyncio.to_thread(self.container_client.login)
                    except Exception as exc:
                        logger.error("Login failed before resolving container IP: %s", exc)
                    target_ip = (
                        self.state.get("container_ip")
                        or await asyncio.to_thread(lambda: self.resolve_container_ip(force_login=False))
                        or await asyncio.to_thread(lambda: self.resolve_container_ip(force_login=True))
                    )
                    if not target_ip:
                        raise ValueError("Container IP unknown; cannot start tunnel.")
                reverse_specs = self._reverse_specs(ssh_cfg)
                dynamic_reverse_specs = self._remote_dynamic_specs(ssh_cfg)
                ports = self._forward_ports(ssh_cfg)
                remote_ports = [spec["remote"] for spec in reverse_specs if spec.get("remote")]
                remote_ports.extend(spec["remote"] for spec in dynamic_reverse_specs if spec.get("remote"))
                intermediate_ports = [spec["mid"] for spec in reverse_specs if spec.get("mid")]
                intermediate_ports.extend(spec["mid"] for spec in dynamic_reverse_specs if spec.get("mid"))
                if reverse_specs or dynamic_reverse_specs:
                    logger.info("Cleaning remote ports before starting: container=%s, intermediate=%s", remote_ports, intermediate_ports)
                    await asyncio.to_thread(
                        self._reverse_cleanup_ports,
                        remote_ports,
                        intermediate_ports,
                        ssh_cfg,
                        target_ip,
                    )
                    await asyncio.sleep(1.0)
                if ports and not await self._ensure_ports_free(ports):
                    self.state["tunnel_status"] = "error"
                    return
                cmd = await asyncio.to_thread(self.build_tunnel_command)
            except Exception as exc:
                logger.error("Cannot build tunnel command: %s", exc)
                self.state["tunnel_status"] = "error"
                return

            logger.info("Starting SSH tunnel: %s", " ".join(cmd))
            proc = await asyncio.create_subprocess_exec(*cmd)
            self._tunnel_process = proc
            self.state["tunnel_status"] = "running"
            self._tunnel_started_once = True

    async def _stop_tunnel_locked(self) -> None:
        """Lock-free tunnel teardown; caller must hold self._proc_lock."""
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

    async def stop_tunnel(self) -> None:
        """停止隧道并更新状态。Safe to call from outside the lock."""
        async with self._proc_lock:
            await self._stop_tunnel_locked()

    async def restart_tunnel(self) -> None:
        """重启隧道刷新转发与端口。"""
        await self.stop_tunnel()
        await self.start_tunnel()
        self._tunnel_config_event.set()

    async def maintain_tunnel(self) -> None:
        """保持隧道存活，异常退出后自动重启。"""
        while not self._stop_requested:
            if not self._has_tunnel_forwards(self._ssh_cfg(reload=True)):
                self.state["tunnel_status"] = "disabled"
                logger.info("No SSH forwards configured for container %s; tunnel maintenance disabled.", self.container_id)
                await self._tunnel_config_event.wait()
                self._tunnel_config_event.clear()
                continue
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
                        ip = await asyncio.to_thread(lambda: self.resolve_container_ip(force_login=True))
                        if not ip:
                            # 如果 IP 仍未获取但登录正常，可尝试读取容器状态，异常则触发重启
                            try:
                                info = (
                                    await asyncio.to_thread(
                                        self.container_client.get_container_instance_info_by_name, name
                                    )
                                    if name
                                    else None
                                )
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
                                result = await self.restart_container(info=info, name_hint=name)
                                if result == "skipped":
                                    logger.info("Container %s status %s appears unhealthy; restart strategy is none, skip restart.", name, status)
                                else:
                                    logger.warning("Container %s status %s appears unhealthy; restart result=%s.", name, status, result)
                        self._tunnel_failure_count = 0
            except Exception as exc:  # pragma: no cover - subprocess errors
                logger.error("SSH tunnel crashed: %s", exc, exc_info=True)
            finally:
                # Only tear down if our captured proc is still the active one;
                # otherwise restart_tunnel already replaced it and is responsible.
                async with self._proc_lock:
                    if self._tunnel_process is proc:
                        await self._stop_tunnel_locked()
            await asyncio.sleep(3)

    async def shutdown(self) -> None:
        """通知循环退出并关闭隧道。"""
        self._stop_requested = True
        self._tunnel_config_event.set()
        await self.stop_tunnel()

    def snapshot(self) -> Dict[str, Any]:
        """获取当前状态（供 Web UI 展示）。"""
        snap = dict(self.state)
        snap["tasks"] = self.list_task_summaries(reload=False)
        try:
            acs_cfg = self._acs_cfg(reload=False)
            snap["configured_container_name"] = acs_cfg.get("container_name")
            snap["service_type"] = (acs_cfg.get("service_type") or "container").lower()
        except Exception:
            pass
        if not snap.get("container_ip"):
            try:
                ssh_cfg = self._ssh_cfg(reload=False)
                fallback_ip = ssh_cfg.get("container_ip") if isinstance(ssh_cfg, dict) else None
                if fallback_ip:
                    snap["container_ip"] = fallback_ip
                    snap.setdefault("ip_source", "fallback")
            except Exception:
                pass
        return snap

    async def prepare_on_start(self, wait_interval: int = 5, start_timeout: int = 300) -> None:
        """启动阶段：登录后检查容器状态，Waiting 等待，Stopped 重启，Running 继续。"""
        name = self.configured_container_name(reload=True)
        if not name:
            logger.warning("acs.container_name not configured or placeholder; skip startup check.")
            return

        try:
            await asyncio.to_thread(self.container_client.login)
            logger.info("Logged in to ACS for startup check.")
        except Exception as exc:
            logger.error("Login failed during startup preparation: %s", exc)
            return

        def _fetch_with_current_name() -> tuple[Optional[str], Optional[Dict[str, Any]]]:
            current_name = self.configured_container_name(reload=True)
            if not current_name:
                return None, None
            try:
                info = self._fetch_info_sync(current_name)
            except Exception as exc:
                logger.error("Failed to fetch container info for %s: %s", current_name, exc, exc_info=True)
                return current_name, None
            return current_name, info

        name, info = await asyncio.to_thread(_fetch_with_current_name)
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
                latest_name, latest = await asyncio.to_thread(_fetch_with_current_name)
                if not latest:
                    await asyncio.sleep(wait_interval)
                    continue
                status_local = (latest.get("status") or "").lower()
                self.update_container_status(latest.get("status"), latest.get("startTime") or latest.get("createTime"))
                ip_local = latest.get("instanceIp")
                if ip_local:
                    await self.handle_new_ip(ip_local)
                if status_local == "running":
                    await self._maybe_run_auto_tasks(latest)
                    logger.info("Container %s is now running; continue startup.", latest_name)
                    return
                if status_local == "waiting":
                    logger.info("Container %s still waiting; polling...", latest_name)
                else:
                    logger.info("Container %s status=%s; waiting for running...", latest_name, status_local)
                await asyncio.sleep(wait_interval)
            logger.warning("Timeout waiting for container %s to reach running state.", self.configured_container_name(reload=True) or name)

        if status == "waiting":
            logger.info("Container %s is Waiting; polling until it starts.", name)
            await _wait_for_running()
        elif status in {"terminated", "stopped", "stop", "failed"}:
            logger.warning("Container %s is stopped (%s); attempting to start.", name, status)
            result = await self.restart_container(info=info, name_hint=name)
            if result == "skipped":
                logger.info("Container %s startup restart skipped because restart strategy is none.", name)
            elif result in {"restarted", "recreated"}:
                await _wait_for_running()
        else:
            if status == "running":
                await self._maybe_run_auto_tasks(info)
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
        if strategy not in {"restart", "recreate", "none"}:
            strategy = "restart"
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
