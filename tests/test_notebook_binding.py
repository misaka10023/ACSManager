from __future__ import annotations

import asyncio
import copy
import json
import unittest
from typing import Any, Dict

from fastapi import HTTPException

from acs_manager.config.scoped import ContainerScopedStore
from acs_manager.container.client import ContainerClient
from acs_manager.management.controller import ContainerManager
from acs_manager.management.multi_manager import MultiContainerManager
from acs_manager.webui import app as webui_app


class DictStore:
    def __init__(self, root: Dict[str, Any]) -> None:
        self.root = copy.deepcopy(root)

    def read(self, *, reload: bool = False) -> Dict[str, Any]:
        return copy.deepcopy(self.root)

    def write(self, data: Dict[str, Any]) -> Dict[str, Any]:
        self.root = copy.deepcopy(data)
        return self.read()

    def get_section(
        self,
        key: str,
        default: Dict[str, Any] | None = None,
        *,
        reload: bool = False,
    ) -> Dict[str, Any]:
        value = self.root.get(key, default or {})
        return copy.deepcopy(value if isinstance(value, dict) else default or {})

    def update(self, changes: Dict[str, Any]) -> Dict[str, Any]:
        for key, value in changes.items():
            if isinstance(value, dict) and isinstance(self.root.get(key), dict):
                self.root[key] = {**self.root[key], **copy.deepcopy(value)}
            else:
                self.root[key] = copy.deepcopy(value)
        return self.read()


class FakeHttpError(RuntimeError):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"HTTP {status_code}")
        self.response = type("Response", (), {"status_code": status_code})()


class NotebookBindingTests(unittest.TestCase):
    def make_client(self, acs: Dict[str, Any] | None = None) -> ContainerClient:
        return ContainerClient(DictStore({"acs": acs or {"service_type": "notebook"}}))  # type: ignore[arg-type]

    def test_notebook_runtime_lookup_requires_exact_name_and_propagates_errors(self) -> None:
        client = self.make_client()
        client.list_notebook_tasks = lambda **_: {  # type: ignore[method-assign]
            "data": [
                {"id": "n1", "notebookName": "job_1_20260101000000"},
                {"id": "n2", "notebookName": "job-other"},
            ]
        }

        exact = client.find_instance_by_name("job_1_20260101000000")
        fuzzy = client.find_instance_by_name("job")

        self.assertEqual(exact and exact.get("id"), "n1")
        self.assertIsNone(fuzzy)

        def fail(**_: Any) -> Dict[str, Any]:
            raise FakeHttpError(502)

        client.list_notebook_tasks = fail  # type: ignore[method-assign]
        with self.assertRaises(FakeHttpError):
            client.find_instance_by_name("job_1_20260101000000")

    def test_configured_notebook_id_bypasses_task_list(self) -> None:
        client = self.make_client(
            {
                "service_type": "notebook",
                "container_name": "job",
                "notebook_id": "notebook-id",
            }
        )
        calls: list[str] = []

        def direct_lookup(notebook_id: str) -> Dict[str, Any]:
            calls.append(notebook_id)
            return {"id": notebook_id, "instanceIp": "10.0.0.8"}

        client.get_notebook_instance_info = direct_lookup  # type: ignore[method-assign]
        client.find_instance_by_name = lambda *_args, **_kwargs: self.fail("task list lookup was used")  # type: ignore[method-assign]

        info = client.get_container_instance_info_by_name("job")

        self.assertEqual(calls, ["notebook-id"])
        self.assertEqual(info and info.get("instanceIp"), "10.0.0.8")

    def test_notebook_monitor_ip_skips_runtime_instance_queries(self) -> None:
        client = self.make_client()
        client.get_notebook_record_detail = lambda _id: {  # type: ignore[method-assign]
            "data": {"id": "n1", "instanceId": "runtime-id", "notebookName": "job"}
        }
        client.get_notebook_monitor = lambda _id: {  # type: ignore[method-assign]
            "data": {"status": "Running", "instanceIp": "10.0.0.9"}
        }
        client.get_notebook_task_detail = lambda _id: self.fail("runtime detail was queried")  # type: ignore[method-assign]
        client.get_task_instance = lambda *_args, **_kwargs: self.fail("runtime instance was queried")  # type: ignore[method-assign]

        info = client.get_notebook_instance_info("n1")

        self.assertEqual(info.get("instanceIp"), "10.0.0.9")
        self.assertEqual(info.get("ipSource"), "api.notebook.monitor")
        self.assertEqual(info.get("status"), "Running")

    def test_direct_notebook_lookup_propagates_total_upstream_failure(self) -> None:
        client = self.make_client()
        client.get_notebook_record_detail = lambda _id: (_ for _ in ()).throw(FakeHttpError(502))  # type: ignore[method-assign]
        client.get_notebook_monitor = lambda _id: (_ for _ in ()).throw(FakeHttpError(502))  # type: ignore[method-assign]

        with self.assertRaises(FakeHttpError):
            client.get_notebook_instance_info("n1")

    def test_running_detail_does_not_mask_monitor_failure(self) -> None:
        client = self.make_client()
        client.get_notebook_record_detail = lambda _id: {  # type: ignore[method-assign]
            "data": {"id": "n1", "notebookName": "job", "status": "Running"}
        }
        client.get_notebook_monitor = lambda _id: (_ for _ in ()).throw(FakeHttpError(502))  # type: ignore[method-assign]

        with self.assertRaises(FakeHttpError):
            client.get_notebook_instance_info("n1")

    def test_notebook_suggestion_failure_is_not_reported_as_empty_list(self) -> None:
        client = self.make_client()
        client.list_notebook_tasks = lambda **_: (_ for _ in ()).throw(FakeHttpError(502))  # type: ignore[method-assign]

        with self.assertRaises(FakeHttpError):
            client.list_task_suggestions(service_type="notebook")

    def test_legacy_exact_match_persists_notebook_binding(self) -> None:
        store = DictStore(
            {
                "acs": {"service_type": "notebook", "container_name": "job"},
                "ssh": {},
                "restart": {},
            }
        )

        class FakeClient:
            def login(self) -> None:
                return None

            def get_container_instance_info_by_name(self, _name: str) -> Dict[str, Any]:
                return {
                    "id": "n1",
                    "notebookName": "job",
                    "status": "Running",
                    "instanceIp": "10.0.0.10",
                    "ipSource": "api.notebook.monitor",
                }

        manager = ContainerManager(store, container_client=FakeClient())  # type: ignore[arg-type]

        ip = manager.resolve_container_ip()

        self.assertEqual(ip, "10.0.0.10")
        self.assertEqual(store.root["acs"]["notebook_id"], "n1")
        self.assertEqual(store.root["acs"]["service_type"], "notebook")
        self.assertEqual(manager.snapshot()["probe_status"], "resolved")

    def test_probe_error_marks_cached_ip_stale(self) -> None:
        store = DictStore(
            {
                "acs": {"service_type": "notebook", "container_name": "job", "notebook_id": "n1"},
                "ssh": {"container_ip": "10.0.0.11"},
                "restart": {},
            }
        )

        class FakeClient:
            def login(self) -> None:
                return None

            def get_container_instance_info_by_name(self, _name: str) -> Dict[str, Any]:
                raise FakeHttpError(502)

        manager = ContainerManager(store, container_client=FakeClient())  # type: ignore[arg-type]

        self.assertIsNone(manager.resolve_container_ip())
        self.assertEqual(manager.state["probe_status"], "upstream_error")
        self.assertTrue(manager.state["ip_stale"])
        self.assertEqual(manager.snapshot()["ip_source"], "fallback")

    def test_notebook_recreate_persists_new_name_and_id_together(self) -> None:
        store = DictStore(
            {
                "acs": {"service_type": "notebook", "container_name": "job", "notebook_id": "old-id"},
                "ssh": {},
                "restart": {"strategy": "recreate"},
            }
        )

        class FakeClient:
            def get_notebook_record_detail(self, _id: str) -> Dict[str, Any]:
                return {"data": {"id": "old-id", "notebookName": "job", "type": "jupyter"}}

            def create_notebook_task(self, _payload: Dict[str, Any]) -> Dict[str, Any]:
                return {"code": "0", "data": "new-id", "msg": "success"}

        manager = ContainerManager(store, container_client=FakeClient(), display_name="job")  # type: ignore[arg-type]

        self.assertTrue(manager._recreate_notebook_task("job", {"id": "old-id"}))
        self.assertEqual(store.root["acs"]["notebook_id"], "new-id")
        self.assertEqual(store.root["acs"]["service_type"], "notebook")
        self.assertRegex(store.root["acs"]["container_name"], r"^job_1_\d{14}$")

    def test_notebook_restart_uses_bound_id_without_list_lookup(self) -> None:
        store = DictStore(
            {
                "acs": {"service_type": "notebook", "container_name": "job", "notebook_id": "n1"},
                "ssh": {},
                "restart": {"strategy": "restart"},
            }
        )
        calls: list[str] = []

        class FakeClient:
            def get_notebook_instance_info(self, notebook_id: str) -> Dict[str, Any]:
                calls.append(f"detail:{notebook_id}")
                return {"id": notebook_id, "status": "Stopped", "timeoutLimit": "360:00:00"}

            def find_instance_by_name(self, _name: str) -> Dict[str, Any]:
                raise AssertionError("task list lookup was used")

            def restart_notebook_task(self, notebook_id: str, **_: Any) -> Dict[str, Any]:
                calls.append(f"restart:{notebook_id}")
                return {"code": "0", "msg": "success"}

        manager = ContainerManager(store, container_client=FakeClient())  # type: ignore[arg-type]

        result = asyncio.run(manager.restart_container())

        self.assertEqual(result, "restarted")
        self.assertEqual(calls, ["detail:n1", "restart:n1"])

    def test_scoped_updates_preserve_notebook_id(self) -> None:
        base = DictStore(
            {
                "acs": {"cookies": {"session": "secret"}},
                "containers": [
                    {
                        "name": "c1",
                        "acs": {
                            "container_name": "job",
                            "service_type": "notebook",
                            "notebook_id": "n1",
                        },
                        "ssh": {},
                    }
                ],
            }
        )
        scoped = ContainerScopedStore(base, "c1")  # type: ignore[arg-type]

        scoped.update({"acs": {"container_name": "job-next"}})

        binding = base.root["containers"][0]["acs"]
        self.assertEqual(binding["notebook_id"], "n1")
        self.assertEqual(binding["service_type"], "notebook")
        self.assertIn("cookies", base.root["acs"])

    def test_multi_manager_normalization_preserves_notebook_binding(self) -> None:
        base = DictStore(
            {
                "acs": {"cookies": {"session": "secret"}, "notebook_id": "global-wrong-id"},
                "containers": [
                    {
                        "name": "n1",
                        "acs": {
                            "container_name": "job",
                            "service_type": "notebook",
                            "notebook_id": "record-id",
                        },
                        "ssh": {},
                    }
                ],
            }
        )
        manager = object.__new__(MultiContainerManager)
        manager.base_store = base  # type: ignore[assignment]

        manager.normalize_root()

        self.assertNotIn("notebook_id", base.root["acs"])
        self.assertEqual(base.root["containers"][0]["acs"]["notebook_id"], "record-id")

    def test_webui_config_round_trip_preserves_only_notebook_ids(self) -> None:
        notebook = webui_app._normalize_container_editor(
            {
                "name": "n1",
                "acs": {"container_name": "job", "service_type": "notebook", "notebook_id": "record-id"},
            }
        )
        container = webui_app._normalize_container_editor(
            {
                "name": "c1",
                "acs": {"container_name": "service", "service_type": "container", "notebook_id": "wrong-id"},
            }
        )

        self.assertEqual(notebook["acs"]["notebook_id"], "record-id")
        self.assertEqual(container["acs"]["notebook_id"], "")

    def test_refresh_api_distinguishes_pending_and_upstream_error(self) -> None:
        original_resolver = webui_app._resolve_manager

        class FakeManager:
            def __init__(self, status: str) -> None:
                self.status = status

            def resolve_container_ip(self, *, force_login: bool = True) -> None:
                return None

            def snapshot(self) -> Dict[str, Any]:
                return {
                    "probe_status": self.status,
                    "container_ip": "10.0.0.12",
                    "ip_source": "api.notebook.monitor",
                    "ip_stale": True,
                }

        try:
            webui_app._resolve_manager = lambda _id: FakeManager("pending")  # type: ignore[assignment]
            response = webui_app.refresh_ip("c1", user="")
            self.assertEqual(response.status_code, 202)
            self.assertEqual(json.loads(response.body)["cached_ip"], "10.0.0.12")

            webui_app._resolve_manager = lambda _id: FakeManager("upstream_error")  # type: ignore[assignment]
            with self.assertRaises(HTTPException) as ctx:
                webui_app.refresh_ip("c1", user="")
            self.assertEqual(ctx.exception.status_code, 502)
        finally:
            webui_app._resolve_manager = original_resolver


if __name__ == "__main__":
    unittest.main()
