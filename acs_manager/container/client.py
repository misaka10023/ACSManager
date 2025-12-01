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
    Minimal ACS container client:
    - login with RSA PKCS1 password encryption
    - reuse configured cookies when present
    - fetch container list and IP data via instance-service API
    """

    def __init__(self, store: ConfigStore) -> None:
        self.store = store
        self.session = requests.Session()
        cfg = self._acs_cfg()
        self.base_url = cfg.get("base_url", "").rstrip("/")
        self.api_prefix = (cfg.get("api_prefix") or "").rstrip("/")
        self.session.verify = cfg.get("verify_ssl", True)
        if not self.session.verify:
            requests.packages.urllib3.disable_warnings()  # type: ignore

    def _acs_cfg(self, reload: bool = False) -> Dict[str, Any]:
        return self.store.get_section("acs", default={}, reload=reload)

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

    def _url(self, path: str) -> str:
        prefix = f"{self.api_prefix}" if self.api_prefix else ""
        if prefix and not prefix.startswith("/"):
            prefix = "/" + prefix
        return f"{self.base_url}{prefix}{path}"

    def login(self, auth_code: str = "") -> LoginResult:
        cfg = self._acs_cfg(reload=True)
        username = cfg.get("login_user", "")
        password = cfg.get("login_password", "")
        user_type = cfg.get("user_type", "os")
        public_key_b64 = cfg.get("public_key", "")
        preset_cookies = cfg.get("cookies", {}) or {}
        self.session.verify = cfg.get("verify_ssl", True)
        self.api_prefix = (cfg.get("api_prefix") or "").rstrip("/")
        if not self.session.verify:
            requests.packages.urllib3.disable_warnings()  # type: ignore

        if preset_cookies:
            # 直接复用配置中的 Cookie
            self._seed_cookies(preset_cookies)
            return LoginResult(True, None, self.session.cookies.get_dict(), {"msg": "use preset cookies"})

        if not username or not password or not public_key_b64 or not self.base_url:
            raise ValueError("缺少 ACS 登录配置（用户名/密码/公钥/base_url）")

        # 预热 session
        self.session.get(self._url("/login.html"))

        enc_pwd = self._encrypt_password(password, public_key_b64)
        payload = {
            "strUserName": username,
            "strPassword": enc_pwd,
            "strUserType": user_type,
            "authCode": auth_code,
            "encrypted": True,
        }
        resp = self.session.post(self._url("/login/loginAuth.action"), data=payload)
        resp.raise_for_status()
        data = resp.json()
        cookies = self.session.cookies.get_dict()
        return LoginResult(
            success=bool(data.get("success")),
            role_id=data.get("roleId"),
            cookies=cookies,
            raw=data,
        )

    def get_cookies(self) -> Dict[str, str]:
        """Return current session cookies."""
        return self.session.cookies.get_dict()

    def get_instance_ips(self, instance_id: str) -> Dict[str, Any]:
        """
        Fetch instance IP information via instance-service.
        """
        url = self._url(f"/api/instance-service/{instance_id}/run-ips")
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def list_tasks(self, start: int = 0, limit: int = 50, sort: str = "DESC") -> Dict[str, Any]:
        """List container tasks (instance-service task endpoint)."""
        url = self._url("/api/instance-service/task")
        resp = self.session.get(url, params={"start": start, "limit": limit, "sort": sort})
        resp.raise_for_status()
        return resp.json()

    def get_run_ips(self, instance_service_id: str) -> Dict[str, Any]:
        """Fetch run-ips by instance service id."""
        url = self._url(f"/api/instance-service/{instance_service_id}/run-ips")
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def find_instance_by_name(self, name: str, *, start: int = 0, limit: int = 50) -> Optional[Dict[str, Any]]:
        """Find first task matching the given name (exact or contains/startswith)."""
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
        """Resolve container info (first run-ips record) by service/task name."""
        task = self.find_instance_by_name(name)
        if not task:
            return None
        service_id = task.get("id") or task.get("instanceServiceId")
        if not service_id:
            return None
        run_ips = self.get_run_ips(service_id)
        ips = run_ips.get("data") or []
        return ips[0] if ips else None

    def get_container_ip_by_name(self, name: str) -> Optional[str]:
        """
        Look up container by service/task name and return its instanceIp if available.
        """
        info = self.get_container_instance_info_by_name(name)
        return info.get("instanceIp") if info else None

    def restart_task(self, task_id: str) -> Dict[str, Any]:
        """
        Call restart API for a task/instance.
        """
        url = self._url("/api/instance-service/task/actions/restart")
        resp = self.session.post(url, json={"id": task_id})
        resp.raise_for_status()
        return resp.json()
