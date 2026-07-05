from __future__ import annotations

import copy
import unittest
from typing import Any, Dict

from acs_manager.management.controller import ContainerManager


class FakeStore:
    def __init__(self, root: Dict[str, Any]) -> None:
        self.root = root

    def read(self, *, reload: bool = False) -> Dict[str, Any]:
        return copy.deepcopy(self.root)


class TaskRunnerTests(unittest.TestCase):
    def make_manager(self, root: Dict[str, Any] | None = None) -> ContainerManager:
        return ContainerManager(
            FakeStore(root or {"tasks": []}),  # type: ignore[arg-type]
            container_client=object(),  # type: ignore[arg-type]
            container_id="c1",
        )

    def test_task_config_preserves_tmux_runner(self) -> None:
        manager = self.make_manager(
            {
                "tasks": [
                    {
                        "id": "svc",
                        "title": "Service",
                        "command": "python app.py",
                        "runner": {"type": "tmux", "session": "svc"},
                    }
                ]
            }
        )

        tasks = manager._task_cfgs(reload=True)

        self.assertEqual(tasks[0]["runner"]["type"], "tmux")
        self.assertEqual(tasks[0]["runner"]["session"], "svc")

    def test_tmux_runner_launches_new_session(self) -> None:
        manager = self.make_manager()
        commands: list[str] = []

        def fake_run(remote_command: str, **_: Any) -> Dict[str, Any]:
            commands.append(remote_command)
            if remote_command.startswith("tmux has-session"):
                return {"ok": False, "returncode": 1, "stdout": "", "stderr": ""}
            return {"ok": True, "returncode": 0, "stdout": "", "stderr": ""}

        manager._run_remote_shell = fake_run  # type: ignore[method-assign]

        result = manager._execute_task_sync(
            {
                "id": "svc",
                "title": "Service",
                "command": "python app.py",
                "workdir": "",
                "log_file": "",
                "runner": {"type": "tmux", "session": "svc"},
            }
        )

        launch_commands = [cmd for cmd in commands if cmd.startswith("tmux new-session")]
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "started")
        self.assertEqual(len(launch_commands), 1)
        self.assertIn("tmux new-session -d -s svc", launch_commands[0])
        self.assertIn("bash -lc", launch_commands[0])
        self.assertIn("/tmp/acs-manager-c1-svc.running", launch_commands[0])

    def test_tmux_runner_uses_marker_to_detect_running_command(self) -> None:
        manager = self.make_manager()
        commands: list[str] = []

        def fake_run(remote_command: str, **_: Any) -> Dict[str, Any]:
            commands.append(remote_command)
            if "&& [ -f /tmp/acs-manager-c1-svc.running ]" in remote_command:
                return {"ok": True, "returncode": 0, "stdout": "", "stderr": ""}
            return {"ok": False, "returncode": 1, "stdout": "", "stderr": ""}

        manager._run_remote_shell = fake_run  # type: ignore[method-assign]

        result = manager._execute_task_sync(
            {
                "id": "svc",
                "title": "Service",
                "command": "python app.py",
                "workdir": "",
                "log_file": "",
                "runner": {"type": "tmux", "session": "svc"},
            }
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "already_running")
        self.assertFalse(any(cmd.startswith("tmux new-session") for cmd in commands))


if __name__ == "__main__":
    unittest.main()
