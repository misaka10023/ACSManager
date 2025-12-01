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
    - fetch container IP data via instance-service API
    """

    def __init__(self, store: ConfigStore) -> None:
        self.store = store
        self.session = requests.Session()
        self.base_url = self._acs_cfg().get("base_url", "").rstrip("/")

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

    def login(self, auth_code: str = "") -> LoginResult:
        cfg = self._acs_cfg(reload=True)
        username = cfg.get("login_user", "")
        password = cfg.get("login_password", "")
        user_type = cfg.get("user_type", "os")
        public_key_b64 = cfg.get("public_key", "")
        preset_cookies = cfg.get("cookies", {}) or {}

        if not username or not password or not public_key_b64 or not self.base_url:
            raise ValueError("Missing ACS login config (username/password/public_key/base_url).")

        if preset_cookies:
            self._seed_cookies(preset_cookies)

        # prime session cookies
        self.session.get(f"{self.base_url}/login.html")

        enc_pwd = self._encrypt_password(password, public_key_b64)
        payload = {
            "strUserName": username,
            "strPassword": enc_pwd,
            "strUserType": user_type,
            "authCode": auth_code,
            "encrypted": True,
        }
        resp = self.session.post(f"{self.base_url}/login/loginAuth.action", data=payload)
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
        url = f"{self.base_url}/api/instance-service/{instance_id}/run-ips"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()
