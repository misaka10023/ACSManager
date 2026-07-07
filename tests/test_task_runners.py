from __future__ import annotations

import asyncio
import copy
import unittest
from typing import Any, Dict

from acs_manager.management.controller import ContainerManager


class FakeStore:
    def __init__(self, root: Dict[str, Any]) -> None:
        self.root = root

    def read(self, *, reload: bool = False) -> Dict[str, Any]:
        return copy.deepcopy(self.root)


class MemoryStateStore:
    def __init__(self) -> None:
        self.tasks: Dict[tuple[str, str], Dict[str, Any]] = {}

    def read_task(self, container_id: str, task_id: str) -> Dict[str, Any]:
        return copy.deepcopy(self.tasks.get((container_id, task_id), {}))

    def update_task(self, container_id: str, task_id: str, changes: Dict[str, Any]) -> Dict[str, Any]:
        key = (container_id, task_id)
        current = copy.deepcopy(self.tasks.get(key, {}))
        current.update(changes)
        self.tasks[key] = current
        return copy.deepcopy(current)


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

    def test_auto_ensure_running_reconciles_same_start_marker(self) -> None:
        manager = self.make_manager(
            {
                "tasks": [
                    {
                        "id": "svc",
                        "title": "Service",
                        "enabled": True,
                        "trigger": "auto_on_start",
                        "mode": "ensure_running",
                        "command": "python app.py",
                        "runner": {"type": "tmux", "session": "svc"},
                    }
                ]
            }
        )
        manager.bind_state_store(MemoryStateStore())  # type: ignore[arg-type]
        calls: list[tuple[str, str]] = []

        async def fake_execute(task_id: str, *, force: bool = False, reason: str = "manual") -> Dict[str, Any]:
            calls.append((task_id, reason))
            return {"success": True, "status": "already_running"}

        manager.execute_task = fake_execute  # type: ignore[method-assign]

        marker_info = {"startTime": "2026-01-01 00:00:00"}
        asyncio.run(manager._maybe_run_auto_tasks(marker_info))
        asyncio.run(manager._maybe_run_auto_tasks(marker_info))

        self.assertEqual(calls, [("svc", "auto_on_start"), ("svc", "auto_on_start")])
        self.assertEqual(manager._task_state("svc").get("last_auto_marker"), marker_info["startTime"])

    def test_auto_once_skips_same_start_marker_after_success(self) -> None:
        manager = self.make_manager(
            {
                "tasks": [
                    {
                        "id": "job",
                        "title": "Job",
                        "enabled": True,
                        "trigger": "auto_on_start",
                        "mode": "once",
                        "command": "python train.py",
                        "runner": {"type": "nohup"},
                    }
                ]
            }
        )
        manager.bind_state_store(MemoryStateStore())  # type: ignore[arg-type]
        calls: list[tuple[str, str]] = []

        async def fake_execute(task_id: str, *, force: bool = False, reason: str = "manual") -> Dict[str, Any]:
            calls.append((task_id, reason))
            return {"success": True, "status": "started"}

        manager.execute_task = fake_execute  # type: ignore[method-assign]

        marker_info = {"startTime": "2026-01-01 00:00:00"}
        asyncio.run(manager._maybe_run_auto_tasks(marker_info))
        asyncio.run(manager._maybe_run_auto_tasks(marker_info))

        self.assertEqual(calls, [("job", "auto_on_start")])

    def test_ensure_running_rejects_nohup_runner(self) -> None:
        manager = self.make_manager(
            {
                "tasks": [
                    {
                        "id": "svc",
                        "title": "Service",
                        "enabled": True,
                        "mode": "ensure_running",
                        "command": "python app.py",
                        "runner": {"type": "nohup"},
                    }
                ]
            }
        )

        with self.assertRaisesRegex(ValueError, "use screen or tmux"):
            asyncio.run(manager.execute_task("svc"))

    def test_auto_shell_runner_records_failed_state(self) -> None:
        manager = self.make_manager(
            {
                "tasks": [
                    {
                        "id": "job",
                        "title": "Job",
                        "enabled": True,
                        "trigger": "auto_on_start",
                        "mode": "once",
                        "command": "python train.py",
                        "runner": {"type": "shell"},
                    }
                ]
            }
        )
        manager.bind_state_store(MemoryStateStore())  # type: ignore[arg-type]

        with self.assertLogs("acs_manager.management.controller", level="ERROR"):
            asyncio.run(manager._maybe_run_auto_tasks({"startTime": "2026-01-01 00:00:00"}))

        task_state = manager._task_state("job")
        self.assertEqual(task_state.get("last_status"), "failed")
        self.assertIn("shell runner", task_state.get("last_message", ""))


if __name__ == "__main__":
    unittest.main()
