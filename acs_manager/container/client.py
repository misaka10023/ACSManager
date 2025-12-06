# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import datetime as dt
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests
from requests import HTTPError
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

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
    def login(self, auth_code: str = "") -> LoginResult:
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
        preset_cookies = {k: v for k, v in (cfg.get("cookies", {}) or {}).items() if v}

        if preset_cookies:
            # 直接复用配置中的 Cookie
            self.session.cookies.clear()
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
                    self.login()
                except Exception:
                    pass
                return self._request_json(method, url, retry_login=True, **kwargs)
            raise

    def list_tasks(self, start: int = 0, limit: int = 20, sort: str = "DESC") -> Dict[str, Any]:
        """获取任务列表：/api/instance-service/task。"""
        url = self._url_api("/api/instance-service/task")
        return self._request_json("get", url, params={"start": start, "limit": limit, "sort": sort})

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

    def get_run_ips(self, instance_service_id: str) -> Dict[str, Any]:
        """通过 run-ips 获取容器 IP 列表。"""
        url = self._url_api(f"/api/instance-service/{instance_service_id}/run-ips")
        return self._request_json("get", url)

    def get_container_monitor(self, instance_service_id: str) -> Dict[str, Any]:
        """获取容器运行状态详情（container-monitor 接口）。"""
        url = self._url_api(f"/api/instance/{instance_service_id}/container-monitor")
        return self._request_json("get", url)

    def find_instance_by_name(self, name: str, *, start: int = 0, limit: int = 50) -> Optional[Dict[str, Any]]:
        """
        按名称匹配任务，返回“最新”的一条匹配记录。

        匹配规则：
        - 先筛出名称完全相等的任务（instanceServiceName/taskName/notebookName/name 中任一等于目标）；
        - 若没有完全相等，再从“前缀/包含”匹配的候选中挑选；
        - 在候选集中按 startTime/createTime 解析后的时间排序，返回最新一条。
        """
        target_raw = name.strip()
        target = target_raw.lower()
        data = self.list_tasks(start=start, limit=limit)
        exact: List[Dict[str, Any]] = []
        fuzzy: List[Dict[str, Any]] = []
        for item in data.get("data", []):
            for key in ("instanceServiceName", "taskName", "notebookName", "name"):
                cand = str(item.get(key, "")).strip()
                cand_l = cand.lower()
                if not cand:
                    continue
                if cand_l == target:
                    exact.append(item)
                    break
                if cand_l.startswith(target) or target in cand_l:
                    fuzzy.append(item)
                    break
        candidates: List[Dict[str, Any]] = exact or fuzzy
        if not candidates:
            return None

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
            # 无法解析时间时，放到最旧
            return dt.datetime.min

        # 选出时间最新的候选
        best = max(candidates, key=_parse_time)
        return best

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
        task = self.find_instance_by_name(name)
        if not task:
            return None
        service_id = task.get("instanceServiceId") or task.get("id")
        if not service_id:
            return None

        monitor = self.get_container_monitor(service_id)
        info: Optional[Dict[str, Any]] = None
        if isinstance(monitor, dict):
            if isinstance(monitor.get("data"), dict):
                info = monitor["data"]
            elif monitor:
                info = monitor
        if not info:
            return None

        # 尝试使用 related-tasks 中最新的一条记录来确定开始时间/超时时间等
        latest_task: Optional[Dict[str, Any]] = None
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

        # IP：related-tasks/任务列表中如有，优先用；否则查询 run-ips
        if not info.get("instanceIp"):
            if source_task.get("instanceIp"):
                info["instanceIp"] = source_task.get("instanceIp")
            else:
                run_ips = self.get_run_ips(service_id)
                ips = run_ips.get("data") or []
                if ips:
                    info["instanceIp"] = ips[0].get("instanceIp")

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
