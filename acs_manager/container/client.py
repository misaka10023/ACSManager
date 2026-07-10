# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import datetime as dt
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests
from requests import HTTPError
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from acs_manager.common.ip_utils import extract_ip as _shared_extract_ip
from acs_manager.config.store import ConfigStore


@dataclass
class LoginResult:
    """ACS 登录结果封装。"""

    success: bool
    role_id: Optional[str]
    cookies: Dict[str, str]
    raw: Dict[str, Any]


class ContainerClient:
    """
    ACS API 客户端：负责登录、任务列表、容器 IP / 状态查询和重启等操作。

    设计要点：
    - 只使用配置里的 base_url / api_prefix / verify_ssl，不再“猜” URL。
    - 登录时支持：
      - 直接复用配置中的 cookies（JSESSIONID / GV_JSESSIONID 等）；
      - 或根据 public_key 对密码加密后调用 loginAuth。
    - 容器状态信息综合以下几个接口：
      - /api/instance-service/task                （任务列表）
      - /api/instance-service/related-tasks       （同一 instanceServiceId 的相关任务，获取最新 startTime）
      - /api/instance/{id}/container-monitor      （运行状态监控）
      - /api/instance-service/{id}/run-ips        （运行 IP 列表）
    """

    def __init__(self, store: ConfigStore) -> None:
        self.store = store
        self.session = requests.Session()
        self.base_url = ""
        self.api_prefix = ""
        self._apply_cfg()

    # -----------------------
    # 配置 & 通用工具
    # -----------------------
    def _acs_cfg(self, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("acs", default={}, reload=reload)

    def _apply_cfg(self, reload: bool = False) -> Dict[str, Any]:
        """从配置加载 base_url / api_prefix / verify_ssl。"""
        cfg = self._acs_cfg(reload=reload)
        self.base_url = (cfg.get("base_url") or "").rstrip("/")
        self.api_prefix = self._normalize_prefix(cfg.get("api_prefix") or "")
        self.session.verify = cfg.get("verify_ssl", True)
        if not self.session.verify:
            # 自签证书场景关闭告警
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        return cfg

    @staticmethod
    def _normalize_prefix(prefix: str) -> str:
        prefix = prefix.strip()
        if not prefix:
            return ""
        if not prefix.startswith("/"):
            prefix = "/" + prefix
        return prefix.rstrip("/")

    def _encrypt_password(self, password: str, public_key_b64: str) -> str:
        """使用配置中的 Base64 公钥对密码做 RSA 加密。"""
        pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + public_key_b64
            + "\n-----END PUBLIC KEY-----"
        )
        key = RSA.import_key(pem)
        cipher = PKCS1_v1_5.new(key)
        ciphertext = cipher.encrypt(password.encode("utf-8"))
        return base64.b64encode(ciphertext).decode("ascii")

    def _seed_cookies(self, cookies: Dict[str, str]) -> None:
        for k, v in cookies.items():
            self.session.cookies.set(k, v)

    def _url_api(self, path: str) -> str:
        """带 api_prefix 的业务接口 URL。"""
        if not path.startswith("/"):
            path = "/" + path
        if not self.base_url:
            raise ValueError("未配置 acs.base_url，无法构造请求 URL。")
        base = self.base_url.rstrip("/")
        prefix = self.api_prefix
        # 若 base_url 已经包含相同前缀则不重复拼接
        if prefix and base.endswith(prefix.lstrip("/")):
            prefix = ""
        return f"{base}{prefix}{path}"

    def _url_raw(self, path: str) -> str:
        """不带 api_prefix 的 URL（登录页/登录接口）。"""
        if not path.startswith("/"):
            path = "/" + path
        if not self.base_url:
            raise ValueError("未配置 acs.base_url，无法构造请求 URL。")
        return f"{self.base_url.rstrip('/')}{path}"

    # -----------------------
    # 登录相关
    # -----------------------
    def login(self, auth_code: str = "", *, force: bool = False) -> LoginResult:
        """
        登录 ACS：
        - 若 acs.cookies 已配置（且非空）则直接复用；
        - 否则按用户名/密码 + 公钥加密方式登录，并把 cookies 回写到配置。
        """
        cfg = self._apply_cfg(reload=True)
        username = cfg.get("login_user", "")
        password = cfg.get("login_password", "")
        user_type = cfg.get("user_type", "os")
        public_key_b64 = cfg.get("public_key", "")
        preset_cookies = {} if force else {k: v for k, v in (cfg.get("cookies", {}) or {}).items() if v}

        self.session.cookies.clear()

        if preset_cookies:
            # 直接复用配置中的 Cookie
            self._seed_cookies(preset_cookies)
            return LoginResult(True, None, self.session.cookies.get_dict(), {"msg": "use preset cookies"})

        if not username or not password or not public_key_b64 or not self.base_url:
            raise ValueError("缺少 ACS 登录配置（用户名/密码/公钥/base_url）。")

        # 预热 session（真实登录页，无前缀）
        self.session.get(self._url_raw("/login/loginPage.action"))

        enc_pwd = self._encrypt_password(password, public_key_b64)
        payload = {
            "strUserName": username,
            "strPassword": enc_pwd,
            "strUserType": user_type,
            "authCode": auth_code,
            "encrypted": True,
        }
        resp = self.session.post(self._url_raw("/login/loginAuth.action"), data=payload)
        resp.raise_for_status()
        data = resp.json()
        cookies = self.session.cookies.get_dict()

        # 持久化最新 cookies 到配置文件，方便后续复用
        if cookies:
            try:
                current_cfg = self._acs_cfg(reload=False)
                new_acs = dict(current_cfg)
                new_acs["cookies"] = cookies
                self.store.update({"acs": new_acs})
            except Exception:
                # 配置写入失败不影响运行
                pass

        return LoginResult(
            success=bool(data.get("success")),
            role_id=data.get("roleId"),
            cookies=cookies,
            raw=data,
        )

    def get_cookies(self) -> Dict[str, str]:
        """返回当前 session cookies。"""
        return self.session.cookies.get_dict()

    # -----------------------
    # 任务 / 容器信息
    # -----------------------
    def _request_json(self, method: str, url: str, *, retry_login: bool = False, **kwargs: Any) -> Dict[str, Any]:
        """统一请求入口：若遇到 401 自动重登一次再重试。"""
        try:
            resp = self.session.request(method, url, **kwargs)
            resp.raise_for_status()
            return resp.json()
        except HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status == 401 and not retry_login:
                try:
                    self.login(force=True)
                except Exception:
                    pass
                return self._request_json(method, url, retry_login=True, **kwargs)
            raise

    def list_tasks(self, start: int = 0, limit: int = 20, sort: str = "DESC") -> Dict[str, Any]:
        """获取任务列表：/api/instance-service/task。"""
        url = self._url_api("/api/instance-service/task")
        return self._request_json("get", url, params={"start": start, "limit": limit, "sort": sort})

    def list_notebook_tasks(
        self,
        start: int = 0,
        limit: int = 20,
        sort: str = "DESC",
        *,
        keyword: str = "",
    ) -> Dict[str, Any]:
        """List Notebook tasks from the ACS Notebook service."""
        params: Dict[str, Any] = {"start": start, "limit": limit, "sort": sort}
        if keyword:
            params["notebookName"] = keyword
        url = self._url_api("/api/notebook/task")
        return self._request_json("get", url, params=params)

    def get_related_tasks(self, instance_service_id: str, start: int = 0, limit: int = 20, sort: str = "DESC") -> Dict[str, Any]:
        """
        获取指定 instanceServiceId 的相关任务列表（related-tasks）。

        实际接口：
          /api/instance-service/related-tasks?start=0&limit=20&sort=DESC&id=<instanceServiceId>
        """
        url = self._url_api("/api/instance-service/related-tasks")
        return self._request_json(
            "get",
            url,
            params={
                "start": start,
                "limit": limit,
                "sort": sort,
                "id": instance_service_id,
            },
        )

    def get_instance_detail(self, instance_service_id: str) -> Dict[str, Any]:
        """获取实例详情：/api/instance-service/{id}/detail。"""
        url = self._url_api(f"/api/instance-service/{instance_service_id}/detail")
        return self._request_json("get", url)

    def get_run_ips(self, instance_service_id: str) -> Dict[str, Any]:
        """通过 run-ips 获取容器 IP 列表。"""
        url = self._url_api(f"/api/instance-service/{instance_service_id}/run-ips")
        return self._request_json("get", url)

    def get_container_monitor(self, instance_service_id: str) -> Dict[str, Any]:
        """获取容器运行状态详情（container-monitor 接口）。"""
        url = self._url_api(f"/api/instance/{instance_service_id}/container-monitor")
        return self._request_json("get", url)

    def get_notebook_task_detail(self, task_id: str) -> Dict[str, Any]:
        """获取 notebook/jupyter 任务详情：/api/tasks/{id}。"""
        url = self._url_api(f"/api/tasks/{task_id}")
        return self._request_json("get", url)

    def get_task_instance(
        self,
        task_id: str,
        container_type: str = "worker",
        container_index: int = 0,
    ) -> Dict[str, Any]:
        """获取 notebook/jupyter 任务实例详情：/api/tasks/{id}/instances/{type}/{index}。"""
        url = self._url_api(f"/api/tasks/{task_id}/instances/{container_type}/{container_index}")
        return self._request_json("get", url)

    def get_notebook_record_detail(self, notebook_id: str) -> Dict[str, Any]:
        """Get Notebook task detail from /api/notebook/{id}/detail."""
        url = self._url_api(f"/api/notebook/{notebook_id}/detail")
        return self._request_json("get", url)

    def get_notebook_monitor(self, notebook_id: str) -> Dict[str, Any]:
        """Get Notebook monitor data from /api/notebook/{id}/monitor."""
        url = self._url_api(f"/api/notebook/{notebook_id}/monitor")
        return self._request_json("get", url)

    def _service_type(self, *, reload: bool = False) -> str:
        return str(self._acs_cfg(reload=reload).get("service_type") or "container").strip().lower()

    def configured_notebook_id(self, *, reload: bool = False) -> str:
        """Return the persisted Notebook record ID, if configured."""
        return str(self._acs_cfg(reload=reload).get("notebook_id") or "").strip()

    @staticmethod
    def _task_items(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        data = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            nested = data.get("data")
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
        return []

    @staticmethod
    def _task_name(item: Dict[str, Any], *keys: str) -> str:
        for key in keys:
            value = str(item.get(key, "")).strip()
            if value:
                return value
        return ""

    @staticmethod
    def _parse_task_time(item: Dict[str, Any]) -> dt.datetime:
        for key in ("startTime", "createTime"):
            value = item.get(key)
            if not value:
                continue
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
                try:
                    return dt.datetime.strptime(str(value), fmt)
                except ValueError:
                    continue
        return dt.datetime.min

    @classmethod
    def _extract_ip_candidate(cls, payload: Any) -> Optional[str]:
        """Extract an IP from nested ACS payloads or captured text bodies."""
        return _shared_extract_ip(payload)

    def _match_instance_from_sources(
        self,
        name: str,
        sources: List[tuple[str, List[Dict[str, Any]], tuple[str, ...]]],
        *,
        allow_fuzzy: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Return the newest exact match, optionally falling back to fuzzy candidates."""
        target = name.strip().lower()
        if not target:
            return None
        for source_name, items, name_keys in sources:
            if not items:
                continue
            exact: List[Dict[str, Any]] = []
            fuzzy: List[Dict[str, Any]] = []
            for item in items:
                for key in name_keys:
                    cand = str(item.get(key, "")).strip()
                    cand_l = cand.lower()
                    if not cand:
                        continue
                    if cand_l == target:
                        exact.append(item)
                        break
                    if not allow_fuzzy:
                        continue
                    alias = re.sub(r"_\d+$", "", cand_l) if source_name == "notebook" else cand_l
                    if alias == target:
                        exact.append(item)
                        break
                    if cand_l.startswith(target) or alias.startswith(target) or target in cand_l:
                        fuzzy.append(item)
                        break
            candidates = exact or fuzzy
            if candidates:
                return max(candidates, key=self._parse_task_time)
        return None

    def find_instance_by_name(self, name: str, *, start: int = 0, limit: int = 200) -> Optional[Dict[str, Any]]:
        service_type = self._service_type(reload=False)
        if service_type == "notebook":
            notebook_items = self._task_items(self.list_notebook_tasks(start=start, limit=limit))
            sources = [("notebook", notebook_items, ("notebookName", "taskName", "name"))]
            return self._match_instance_from_sources(name, sources, allow_fuzzy=False)

        container_items = self._task_items(self.list_tasks(start=start, limit=limit))
        sources = [("container", container_items, ("instanceServiceName", "taskName", "notebookName", "name"))]
        return self._match_instance_from_sources(name, sources)

    def find_notebook_task_by_name(self, name: str, *, start: int = 0, limit: int = 200) -> Optional[Dict[str, Any]]:
        """Match only Notebook service records."""
        notebook_items = self._task_items(self.list_notebook_tasks(start=start, limit=limit, keyword=name))
        sources = [("notebook", notebook_items, ("notebookName", "taskName", "name"))]
        return self._match_instance_from_sources(name, sources, allow_fuzzy=False)

    def find_container_task_by_name(self, name: str, *, start: int = 0, limit: int = 200) -> Optional[Dict[str, Any]]:
        """Match only instance-service/container records to recover restartable service IDs."""
        container_items = self._task_items(self.list_tasks(start=start, limit=limit))
        sources = [("container", container_items, ("instanceServiceName", "taskName", "notebookName", "name"))]
        return self._match_instance_from_sources(name, sources)

    def list_task_suggestions(
        self,
        *,
        limit: int = 200,
        service_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return merged task suggestions for Web UI autocomplete."""
        requested_type = str(service_type or "").strip().lower()
        if requested_type not in {"", "container", "notebook"}:
            raise ValueError(f"Unsupported ACS service type: {service_type}")
        suggestions: List[Dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        errors: List[Exception] = []
        successful_sources = 0

        def _append(items: List[Dict[str, Any]], service_type: str, *name_keys: str) -> None:
            for item in items:
                name = self._task_name(item, *name_keys)
                if not name:
                    continue
                task_id = str(item.get("instanceServiceId") or item.get("id") or item.get("taskId") or "")
                key = (service_type, name, task_id)
                if key in seen:
                    continue
                seen.add(key)
                suggestions.append(
                    {
                        "name": name,
                        "status": item.get("status"),
                        "id": task_id or None,
                        "task_type": item.get("taskType") or item.get("type"),
                        "service_type": service_type,
                        "createTime": item.get("createTime"),
                        "startTime": item.get("startTime"),
                    }
                )

        if requested_type in {"", "container"}:
            try:
                _append(
                    self._task_items(self.list_tasks(start=0, limit=limit, sort="DESC")),
                    "container",
                    "instanceServiceName",
                    "taskName",
                    "notebookName",
                    "name",
                )
                successful_sources += 1
            except Exception as exc:
                errors.append(exc)
        if requested_type in {"", "notebook"}:
            try:
                _append(
                    self._task_items(self.list_notebook_tasks(start=0, limit=limit, sort="DESC")),
                    "notebook",
                    "notebookName",
                    "taskName",
                    "name",
                )
                successful_sources += 1
            except Exception as exc:
                errors.append(exc)
        if successful_sources == 0 and errors:
            raise errors[0]
        suggestions.sort(key=self._parse_task_time, reverse=True)
        return suggestions

    def _get_notebook_instance_info(self, task: Dict[str, Any], notebook_id: str) -> Dict[str, Any]:
        errors: List[Exception] = []
        successful_requests = 0
        detail_data: Optional[Dict[str, Any]] = None
        try:
            detail = self.get_notebook_record_detail(notebook_id)
            successful_requests += 1
            raw = detail.get("data") if isinstance(detail, dict) else None
            if isinstance(raw, dict) and raw:
                detail_data = raw
        except Exception as exc:
            errors.append(exc)

        source_task = detail_data or task
        info: Dict[str, Any] = {}

        monitor_data: Optional[Dict[str, Any]] = None
        try:
            monitor = self.get_notebook_monitor(notebook_id)
            successful_requests += 1
            raw = monitor.get("data") if isinstance(monitor, dict) else None
            if isinstance(raw, dict) and raw:
                monitor_data = raw
                info.update(raw)
        except Exception as exc:
            errors.append(exc)

        candidate_ip: Optional[str] = None
        ip_source: Optional[str] = None
        for payload, source in (
            (monitor_data, "api.notebook.monitor"),
            (source_task, "api.notebook.detail"),
            (task, "api.notebook.list"),
        ):
            candidate_ip = self._extract_ip_candidate(payload)
            if candidate_ip:
                ip_source = source
                break

        runtime_task_id = str(
            source_task.get("instanceId")
            or task.get("instanceId")
            or ""
        ).strip()
        runtime_detail: Optional[Dict[str, Any]] = None
        instance_data: Optional[Dict[str, Any]] = None
        if runtime_task_id and not candidate_ip:
            try:
                runtime = self.get_notebook_task_detail(runtime_task_id)
                successful_requests += 1
                raw = runtime.get("data") if isinstance(runtime, dict) else None
                if isinstance(raw, dict) and raw:
                    runtime_detail = raw
                    candidate_ip = self._extract_ip_candidate(raw)
                    if candidate_ip:
                        ip_source = "api.notebook.runtime"
            except Exception as exc:
                errors.append(exc)

            if not candidate_ip:
                for container_type in ("worker", "ps"):
                    try:
                        instance = self.get_task_instance(
                            runtime_task_id,
                            container_type=container_type,
                            container_index=0,
                        )
                        successful_requests += 1
                    except Exception as exc:
                        errors.append(exc)
                        continue
                    raw = instance.get("data") if isinstance(instance, dict) else None
                    if isinstance(raw, dict) and raw:
                        instance_data = raw
                        info.update(raw)
                        info["containerType"] = raw.get("containerType") or container_type
                        candidate_ip = self._extract_ip_candidate(raw)
                        if candidate_ip:
                            ip_source = "api.notebook.runtime"
                        break

        if successful_requests == 0 and errors:
            raise errors[0]

        for source in (monitor_data or {}, instance_data or {}, runtime_detail or {}, source_task, task):
            for key in ("status", "taskStatus"):
                if source.get(key):
                    info["status"] = source.get(key)
                    break
            if info.get("status"):
                break

        status_norm = str(info.get("status") or "").strip().lower()
        no_ip_expected = {
            "waiting",
            "queued",
            "pending",
            "creating",
            "starting",
            "stopped",
            "stop",
            "terminated",
            "failed",
        }
        if not candidate_ip and errors and status_norm not in no_ip_expected:
            raise errors[-1]

        for source in (source_task, monitor_data or {}, runtime_detail or {}, instance_data or {}, task):
            for key in ("startTime", "createTime"):
                if source.get(key):
                    info["startTime"] = source.get(key)
                    break
            if info.get("startTime"):
                break
        for source in (source_task, task, monitor_data or {}):
            if source.get("timeoutLimit"):
                info["timeoutLimit"] = source.get("timeoutLimit")
                break
        for source in (source_task, monitor_data or {}, task):
            remaining = source.get("remainTime") or source.get("remainingTime")
            if remaining:
                info["remainingTime"] = remaining
                break

        if candidate_ip:
            info["instanceIp"] = candidate_ip
            info["ipSource"] = ip_source or "api.notebook"

        info["id"] = source_task.get("id") or task.get("id") or notebook_id
        if source_task.get("instanceId") or task.get("instanceId"):
            info["instanceId"] = source_task.get("instanceId") or task.get("instanceId")
        if runtime_detail and runtime_detail.get("taskId"):
            info["taskId"] = runtime_detail.get("taskId")
        elif source_task.get("taskId") or task.get("taskId"):
            info["taskId"] = source_task.get("taskId") or task.get("taskId")
        for key in ("notebookName", "taskName", "name"):
            value = source_task.get(key) or task.get(key)
            if value:
                info[key] = value
        return info

    def get_notebook_instance_info(self, notebook_id: str) -> Dict[str, Any]:
        """Fetch Notebook state directly by its persisted record ID."""
        record_id = str(notebook_id or "").strip()
        if not record_id:
            raise ValueError("Notebook record ID is required.")
        return self._get_notebook_instance_info({"id": record_id}, record_id)

    def get_container_instance_info_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        按任务/容器名获取详情。

        综合以下来源：
        - instance-service 任务列表
        - related-tasks（同一 instanceServiceId 的最近一次运行）
        - container-monitor
        - run-ips

        返回的 info 中尽量包含：
        - instanceIp
        - status
        - startTime
        - timeoutLimit
        - remainingTime（如有）
        - instanceServiceId
        """
        service_type = self._service_type(reload=False)

        if service_type == "notebook":
            configured_id = self.configured_notebook_id(reload=False)
            if configured_id:
                return self.get_notebook_instance_info(configured_id)

            task = self.find_instance_by_name(name)
            if not task:
                return None
            # Notebook lifecycle endpoints use the record id returned by
            # /api/notebook/task. Runtime instance probes use instanceId.
            notebook_task_id = task.get("id")
            if not notebook_task_id:
                return None
            return self._get_notebook_instance_info(task, str(notebook_task_id))

        task = self.find_instance_by_name(name)
        if not task:
            return None
        service_id = task.get("instanceServiceId") or task.get("id")
        if not service_id:
            return None

        info: Dict[str, Any] = {}
        try:
            monitor = self.get_container_monitor(service_id)
        except Exception:
            monitor = None
        if isinstance(monitor, dict):
            if isinstance(monitor.get("data"), dict):
                info = dict(monitor["data"])
            elif monitor:
                info = dict(monitor)
        if info.get("instanceIp") and not info.get("ipSource"):
            info["ipSource"] = "api.instance-service.monitor"

        # 尝试使用 related-tasks 中最新的一条记录来确定开始时间/超时时间等
        latest_task: Optional[Dict[str, Any]] = None
        if service_type != "notebook":
            try:
                related = self.get_related_tasks(service_id, start=0, limit=20, sort="DESC")
                items = related.get("data") or []
                if items:
                    def _parse_time(item: Dict[str, Any]) -> dt.datetime:
                        for k in ("startTime", "createTime"):
                            v = item.get(k)
                            if not v:
                                continue
                            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
                                try:
                                    return dt.datetime.strptime(str(v), fmt)
                                except ValueError:
                                    continue
                        return dt.datetime.min

                    latest_task = max(items, key=_parse_time)
            except Exception:
                latest_task = None

        if latest_task is None:
            try:
                detail = self.get_instance_detail(service_id)
                detail_data = detail.get("data") if isinstance(detail, dict) else None
                if isinstance(detail_data, dict) and detail_data:
                    latest_task = detail_data
            except Exception:
                latest_task = None

        source_task = latest_task or task

        # 状态字段
        for key in ("status", "instanceStatus", "taskStatus"):
            if source_task.get(key):
                info["status"] = source_task.get(key)
                break

        # 开始时间：优先 startTime，其次 createTime
        for key in ("startTime", "createTime"):
            if source_task.get(key):
                info["startTime"] = source_task.get(key)
                break

        # 超时时长
        if source_task.get("timeoutLimit"):
            info["timeoutLimit"] = source_task.get("timeoutLimit")

        # 剩余时间（仅用于展示）
        if source_task.get("remainingTime"):
            info["remainingTime"] = source_task.get("remainingTime")

        # IP：优先从已有任务/详情字段提取；container 模式再用 run-ips 兜底
        if not info.get("instanceIp"):
            candidate_ip = (
                self._extract_ip_candidate(source_task)
                or self._extract_ip_candidate(info)
                or self._extract_ip_candidate(task)
            )
            if candidate_ip:
                info["instanceIp"] = candidate_ip
                info["ipSource"] = "api.instance-service.detail"
            elif service_type != "notebook":
                run_ips = self.get_run_ips(service_id)
                ips = run_ips.get("data") or []
                if ips:
                    info["instanceIp"] = ips[0].get("instanceIp")
                    info["ipSource"] = "api.instance-service.run-ips"

        info["instanceServiceId"] = service_id
        return info

    def get_container_ip_by_name(self, name: str) -> Optional[str]:
        """按名称获取容器 IP。"""
        info = self.get_container_instance_info_by_name(name)
        return info.get("instanceIp") if info else None

    def restart_task(self, task_id: str) -> Dict[str, Any]:
        """调用重启接口 /api/instance-service/task/actions/restart。"""
        url = self._url_api("/api/instance-service/task/actions/restart")
        return self._request_json("post", url, json={"id": task_id})

    def restart_notebook_task(
        self,
        notebook_id: str,
        *,
        auto_terminated: Any = None,
        timeout_limit: Any = None,
    ) -> Dict[str, Any]:
        """Restart/start a Notebook task through the Notebook service."""
        payload: Dict[str, Any] = {"id": notebook_id}
        if auto_terminated is not None:
            payload["autoTerminated"] = auto_terminated
        if timeout_limit is not None:
            payload["timeoutLimit"] = "" if timeout_limit == "unlimited" else timeout_limit
        url = self._url_api("/api/notebook/task/actions/restart")
        return self._request_json("post", url, json=payload)

    def stop_notebook_tasks(self, notebook_ids: List[str]) -> Dict[str, Any]:
        """Stop Notebook tasks through the Notebook service."""
        url = self._url_api("/api/notebook/task/actions/stop")
        return self._request_json("post", url, json={"ids": notebook_ids})

    def create_task(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """创建新任务 /api/instance-service/task。"""
        url = self._url_api("/api/instance-service/task")
        return self._request_json("post", url, json=payload)

    def create_notebook_task(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Notebook task through /api/notebook/task."""
        url = self._url_api("/api/notebook/task")
        return self._request_json("post", url, json=payload)
