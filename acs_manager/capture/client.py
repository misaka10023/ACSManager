# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Any, Dict

from acs_manager.container import ContainerClient


class CaptureClient:
    """
    High-level helper that uses ContainerClient to obtain cookies and
    query container IP/state via ACS APIs.
    """

    def __init__(self, container_client: ContainerClient) -> None:
        self.container_client = container_client
        self.logged_in = False

    def ensure_login(self) -> Dict[str, str]:
        if not self.logged_in:
            result = self.container_client.login()
            if not result.success:
                raise RuntimeError(f"Login failed: {result.raw}")
            self.logged_in = True
        return self.container_client.get_cookies()

    def get_container_ips(self, instance_id: str) -> Dict[str, Any]:
        self.ensure_login()
        return self.container_client.get_instance_ips(instance_id)

    def get_container_ip_by_name(self, name: str) -> str:
        self.ensure_login()
        ip = self.container_client.get_container_ip_by_name(name)
        if not ip:
            raise RuntimeError(f"Container {name} not found or IP unavailable.")
        return ip
