from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from acs_manager.config.store import ConfigStore


@dataclass
class LoginResult:
    success: bool
    role_id: Optional[str]
    cookies: Dict[str, str]
    raw: Dict[str, Any]


class ContainerClient:
    """
    ACS API 客户端：登录、任务列表、容器 IP/状态查询与重启。
    - 支持配置里的 Cookie 直连；若为空则按公钥加密密码登录
    - 仅使用配置给出的 base_url 与 api_prefix 拼 URL（不再猜测）
    - 通过 instance-service 任务列表、run-ips、container-monitor 获取信息
    """

    def __init__(self, store: ConfigStore) -> None:
        self.store = store
        self.session = requests.Session()
        self.base_url = ""
        self.api_prefix = ""
        self._apply_cfg()

    def _acs_cfg(self, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("acs", default={}, reload=reload)

    def _apply_cfg(self, reload: bool = False) -> Dict[str, Any]:
        """从配置加载 base_url / api_prefix / verify_ssl。"""
        cfg = self._acs_cfg(reload=reload)
        self.base_url = (cfg.get("base_url") or "").rstrip("/")
        self.api_prefix = self._normalize_prefix(cfg.get("api_prefix") or "")
        self.session.verify = cfg.get("verify_ssl", True)
        if not self.session.verify:
            requests.packages.urllib3.disable_warnings()  # type: ignore
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
            raise ValueError("未配置 acs.base_url，无法构建请求 URL。")
        base = self.base_url.rstrip("/")
        prefix = self.api_prefix
        # 若 base_url 已包含相同前缀则不重复拼接
        if prefix and base.endswith(prefix.lstrip("/")):
            prefix = ""
        return f"{base}{prefix}{path}"

    def _url_raw(self, path: str) -> str:
        """不带 api_prefix 的 URL（登录页/登录接口用）。"""
        if not path.startswith("/"):
            path = "/" + path
        if not self.base_url:
            raise ValueError("未配置 acs.base_url，无法构建请求 URL。")
        return f"{self.base_url.rstrip('/')}{path}"

    def login(self, auth_code: str = "") -> LoginResult:
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

        # 预热 session（使用实际登录页，无前缀）
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
        # Persist最新 cookies 到配置文件，便于后续复用
        if cookies:
            try:
                current_cfg = self._acs_cfg(reload=False)
                new_acs = dict(current_cfg)
                new_acs["cookies"] = cookies
                self.store.update({"acs": new_acs})
            except Exception:
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

    def list_tasks(self, start: int = 0, limit: int = 20, sort: str = "DESC") -> Dict[str, Any]:
        """获取任务列表（/sothisai/api/instance-service/task）。"""
        url = self._url_api("/api/instance-service/task")
        resp = self.session.get(url, params={"start": start, "limit": limit, "sort": sort})
        resp.raise_for_status()
        return resp.json()

    def get_run_ips(self, instance_service_id: str) -> Dict[str, Any]:
        """通过 run-ips 获取容器 IP 列表。"""
        url = self._url_api(f"/api/instance-service/{instance_service_id}/run-ips")
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_container_monitor(self, instance_service_id: str) -> Dict[str, Any]:
        """获取容器运行状态详情（container-monitor 接口）。"""
        url = self._url_api(f"/api/instance/{instance_service_id}/container-monitor")
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def find_instance_by_name(self, name: str, *, start: int = 0, limit: int = 50) -> Optional[Dict[str, Any]]:
        """按名称匹配任务，返回第一条匹配记录。"""
        target = name.strip().lower()
        data = self.list_tasks(start=start, limit=limit)
        for item in data.get("data", []):
            for key in ("instanceServiceName", "taskName", "notebookName", "name"):
                cand = str(item.get(key, "")).strip()
                cand_l = cand.lower()
                if not cand:
                    continue
                if cand_l == target or target in cand_l or cand_l.startswith(target):
                    return item
        return None

    def get_container_instance_info_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """按任务/容器名获取详情，优先 container-monitor，缺失字段时从任务列表补充。

        返回的 info 中会尽量包含：
        - instanceIp
        - status
        - startTime
        - timeoutLimit
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

        # 优先使用 container-monitor 的字段，缺失时从任务记录补充
        # 状态字段
        if not info.get("status"):
            for key in ("status", "instanceStatus", "taskStatus"):
                if task.get(key):
                    info["status"] = task.get(key)
                    break
        # 启动时间
        if not info.get("startTime"):
            for key in ("startTime", "createTime", "start_time"):
                if task.get(key):
                    info["startTime"] = task.get(key)
                    break
        # 超时时长
        if not info.get("timeoutLimit") and task.get("timeoutLimit"):
            info["timeoutLimit"] = task.get("timeoutLimit")

        if not info.get("instanceIp"):
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
        resp = self.session.post(url, json={"id": task_id})
        resp.raise_for_status()
        return resp.json()
