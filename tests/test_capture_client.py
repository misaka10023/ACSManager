from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any, Dict

from acs_manager.capture.client import CaptureClient


class FakeContainerClient:
    def __init__(self) -> None:
        self.login_calls = 0
        self.run_ip_calls: list[str] = []

    def login(self) -> SimpleNamespace:
        self.login_calls += 1
        return SimpleNamespace(success=True, raw={"ok": True})

    def get_cookies(self) -> Dict[str, str]:
        return {"JSESSIONID": "token"}

    def get_run_ips(self, instance_id: str) -> Dict[str, Any]:
        self.run_ip_calls.append(instance_id)
        return {"data": [{"instanceIp": "10.0.0.1"}]}


class CaptureClientTests(unittest.TestCase):
    def test_get_container_ips_uses_existing_run_ips_api(self) -> None:
        container_client = FakeContainerClient()
        capture_client = CaptureClient(container_client)  # type: ignore[arg-type]

        result = capture_client.get_container_ips("svc-1")

        self.assertEqual(result, {"data": [{"instanceIp": "10.0.0.1"}]})
        self.assertEqual(container_client.login_calls, 1)
        self.assertEqual(container_client.run_ip_calls, ["svc-1"])


if __name__ == "__main__":
    unittest.main()
