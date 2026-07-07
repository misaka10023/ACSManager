from __future__ import annotations

import copy
import unittest
from typing import Any, Dict

from fastapi import HTTPException

from acs_manager.webui import app as webui_app


class FakeConfigStore:
    def __init__(self, root: Dict[str, Any]) -> None:
        self.root = root

    def get_section(self, key: str, default: Dict[str, Any] | None = None, *, reload: bool = False) -> Dict[str, Any]:
        value = self.root.get(key, default or {})
        return copy.deepcopy(value if isinstance(value, dict) else default or {})


class WebUiSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_config_store = webui_app.config_store

    def tearDown(self) -> None:
        webui_app.config_store = self.original_config_store

    def bind_config(self, root: Dict[str, Any]) -> None:
        webui_app.config_store = FakeConfigStore(root)  # type: ignore[assignment]

    def test_require_auth_allows_disabled_auth_on_loopback_bind(self) -> None:
        self.bind_config({"webui": {"host": "127.0.0.1", "auth": {"enabled": False}}})

        self.assertEqual(webui_app.require_auth(object()), "")  # type: ignore[arg-type]

    def test_require_auth_blocks_disabled_auth_on_public_bind(self) -> None:
        self.bind_config({"webui": {"host": "0.0.0.0", "auth": {"enabled": False}}})

        with self.assertRaises(HTTPException) as ctx:
            webui_app.require_auth(object())  # type: ignore[arg-type]

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("auth is disabled", str(ctx.exception.detail))

    def test_validate_config_rejects_duplicate_persistent_sessions(self) -> None:
        root = webui_app._normalize_root_config(
            {
                "containers": [
                    {
                        "name": "c1",
                        "tasks": [
                            {"id": "svc-a", "command": "python a.py", "runner": {"type": "screen", "session": "svc"}},
                            {"id": "svc-b", "command": "python b.py", "runner": {"type": "screen", "session": "svc"}},
                        ],
                    }
                ]
            }
        )

        with self.assertRaises(HTTPException) as ctx:
            webui_app._validate_root_config(root)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("share screen session", str(ctx.exception.detail))

    def test_validate_config_rejects_ensure_running_without_persistent_runner(self) -> None:
        root = webui_app._normalize_root_config(
            {
                "containers": [
                    {
                        "name": "c1",
                        "tasks": [
                            {
                                "id": "svc",
                                "mode": "ensure_running",
                                "command": "python app.py",
                                "runner": {"type": "nohup"},
                            }
                        ],
                    }
                ]
            }
        )

        with self.assertRaises(HTTPException) as ctx:
            webui_app._validate_root_config(root)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("ensure_running", str(ctx.exception.detail))

    def test_validate_config_rejects_auto_shell_runner(self) -> None:
        root = webui_app._normalize_root_config(
            {
                "containers": [
                    {
                        "name": "c1",
                        "tasks": [
                            {
                                "id": "job",
                                "trigger": "auto_on_start",
                                "command": "python train.py",
                                "runner": {"type": "shell"},
                            }
                        ],
                    }
                ]
            }
        )

        with self.assertRaises(HTTPException) as ctx:
            webui_app._validate_root_config(root)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("shell runner", str(ctx.exception.detail))


if __name__ == "__main__":
    unittest.main()
