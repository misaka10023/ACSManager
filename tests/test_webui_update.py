from __future__ import annotations

import unittest
from pathlib import Path
from typing import List

from acs_manager.webui import app as webui_app


class WebUiUpdateTests(unittest.TestCase):
    def test_check_update_refuses_dirty_worktree_before_fetch(self) -> None:
        calls: List[List[str]] = []
        original_run_git = webui_app._run_git

        def fake_run_git(args: list[str], cwd: Path) -> str:
            calls.append(args)
            if args == ["git", "status", "--porcelain"]:
                return " M README.md"
            raise AssertionError(f"unexpected git command: {args}")

        webui_app._run_git = fake_run_git  # type: ignore[assignment]
        try:
            with self.assertRaisesRegex(RuntimeError, "Working tree has local changes"):
                webui_app._check_update(Path("."))
        finally:
            webui_app._run_git = original_run_git  # type: ignore[assignment]

        self.assertEqual(calls, [["git", "status", "--porcelain"]])


if __name__ == "__main__":
    unittest.main()
