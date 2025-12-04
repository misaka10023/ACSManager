# -*- coding: utf-8 -*-
from __future__ import annotations

import datetime as dt
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from acs_manager.config.store import ConfigStore
from acs_manager.management.controller import ContainerManager

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="ACS Manager UI", version="0.2.0")


class RootPathPrefixMiddleware:
    """Strip configured root_path prefix from incoming requests so routing works under subpaths."""

    def __init__(self, app: FastAPI, prefix: str) -> None:
        self.app = app
        normalized = (prefix or "").rstrip("/")
        if normalized and not normalized.startswith("/"):
            normalized = "/" + normalized
        self.prefix = normalized

    async def __call__(self, scope: dict, receive: Any, send: Any) -> Any:  # type: ignore[override]
        if not self.prefix or scope.get("type") not in {"http", "websocket"}:
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if not path.startswith(self.prefix):
            return await self.app(scope, receive, send)
        new_scope = dict(scope)
        new_scope["root_path"] = self.prefix
        trimmed = path[len(self.prefix) :] or "/"
        new_scope["path"] = trimmed
        return await self.app(new_scope, receive, send)

# mount static assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

manager: Optional[ContainerManager] = None
config_store: Optional[ConfigStore] = None
LOG_DIR = Path("logs")
_root_path_middleware_added = False


def bind_manager(instance: ContainerManager) -> None:
    global manager
    manager = instance


def bind_config_store(store: ConfigStore) -> None:
    global config_store
    config_store = store


def set_root_path(root_path: str | None) -> None:
    """Allow runtime override of app root path for sub-path deployments."""
    global _root_path_middleware_added
    cleaned = (root_path or "").rstrip("/")
    if cleaned and not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    app.root_path = cleaned
    if cleaned and not _root_path_middleware_added:
        app.add_middleware(RootPathPrefixMiddleware, prefix=cleaned)
        _root_path_middleware_added = True


# -----------------------
# JSON API (unchanged)
# -----------------------
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/state")
def state() -> dict:
    if manager is None:
        raise HTTPException(status_code=503, detail="Manager not wired to web UI yet")
    return manager.snapshot()


@app.get("/container-ip")
def container_ip() -> dict:
    if manager is None:
        raise HTTPException(status_code=503, detail="Manager not wired to web UI yet")
    ip = manager.snapshot().get("container_ip")
    source = "captured"
    if not ip:
        try:
            ip = manager.resolve_container_ip(force_login=True)
            source = "api"
        except Exception:
            ip = None
        if not ip and config_store:
            settings = config_store.read(reload=True)
            fallback = settings.get("ssh", {}).get("container_ip")
            if fallback:
                return {
                    "container_ip": fallback,
                    "ip": fallback,
                    "source": "fallback",
                }
        if not ip:
            raise HTTPException(status_code=404, detail="Container IP not available yet")
    payload = {
        "container_ip": ip,
        "ip": ip,
        "source": source,
    }
    if manager and manager.snapshot().get("last_seen"):
        seen = manager.snapshot().get("last_seen")
        if isinstance(seen, dt.datetime):
            payload["updated_at"] = seen.strftime("%Y-%m-%d %H:%M:%S")
    return payload


@app.get("/config")
def get_config(reload: bool = True) -> dict:
    if config_store is None:
        raise HTTPException(status_code=503, detail="Config store not ready")
    return config_store.read(reload=reload)


def _critical_snapshot(cfg: Dict[str, Any]) -> Dict[str, Any]:
    acs = cfg.get("acs", {}) or {}
    ssh = cfg.get("ssh", {}) or {}
    return {
        "acs.base_url": acs.get("base_url"),
        "acs.api_prefix": acs.get("api_prefix"),
        "acs.login_user": acs.get("login_user"),
        "acs.login_password": acs.get("login_password"),
        "acs.public_key": acs.get("public_key"),
        "ssh.mode": ssh.get("mode"),
        "ssh.remote_server_ip": ssh.get("remote_server_ip"),
        "ssh.bastion_host": ssh.get("bastion_host"),
        "ssh.bastion_user": ssh.get("bastion_user"),
        "ssh.target_user": ssh.get("target_user"),
        "ssh.port": ssh.get("port"),
        "ssh.container_port": ssh.get("container_port"),
        "ssh.local_open_port": ssh.get("local_open_port"),
        "ssh.container_open_port": ssh.get("container_open_port"),
        "ssh.forwards": ssh.get("forwards"),
        "ssh.reverse_forwards": ssh.get("reverse_forwards"),
        "ssh.intermediate_port": ssh.get("intermediate_port"),
    }


async def _post_config_change(old_cfg: Dict[str, Any], new_cfg: Dict[str, Any]) -> None:
    """关键配置变更后：重新登录刷新 cookies，并必要时重启 SSH 隧道。"""
    if manager is None:
        return

    before = _critical_snapshot(old_cfg)
    after = _critical_snapshot(new_cfg)

    acs_keys = [k for k in before.keys() if k.startswith("acs.")]
    ssh_keys = [k for k in before.keys() if k.startswith("ssh.")]

    acs_changed = any(before[k] != after[k] for k in acs_keys)
    ssh_changed = any(before[k] != after[k] for k in ssh_keys)

    if acs_changed:
        try:
            logger.info("检测到 ACS 关键配置变更，尝试重新登录以刷新 cookies。")
            manager.container_client.login()  # type: ignore[attr-defined]
        except Exception as exc:  # pragma: no cover - 网络/ACS 异常
            logger.error("重新登录以刷新 ACS cookies 失败: %s", exc)

    if ssh_changed:
        try:
            logger.info("检测到 SSH 关键配置变更，重启隧道以应用新配置。")
            await manager.restart_tunnel()
        except Exception as exc:  # pragma: no cover - 隧道异常
            logger.error("重启 SSH 隧道失败: %s", exc)


@app.patch("/config")
async def patch_config(payload: dict = Body(..., embed=False)) -> dict:
    if config_store is None:
        raise HTTPException(status_code=503, detail="Config store not ready")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload must be an object")
    old_cfg = config_store.read(reload=False)
    new_cfg = config_store.update(payload)
    await _post_config_change(old_cfg, new_cfg)
    return new_cfg


@app.put("/config")
async def replace_config(payload: dict = Body(..., embed=False)) -> dict:
    if config_store is None:
        raise HTTPException(status_code=503, detail="Config store not ready")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload must be an object")
    old_cfg = config_store.read(reload=False)
    new_cfg = config_store.write(payload)
    await _post_config_change(old_cfg, new_cfg)
    return new_cfg


def _latest_log_file() -> Path:
    if not LOG_DIR.exists():
        raise FileNotFoundError("logs directory not found")
    log_files = sorted(LOG_DIR.glob("*.log"))
    if not log_files:
        raise FileNotFoundError("no log file found")
    return log_files[-1]


@app.get("/logs")
def tail_logs(lines: int = Query(200, ge=1, le=2000)) -> dict:
    """Return the tail of the latest log file."""
    try:
        log_path = _latest_log_file()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    content_lines = log_path.read_text(encoding="utf-8").splitlines()
    tail = content_lines[-lines:] if len(content_lines) > lines else content_lines
    return {"file": str(log_path), "lines": len(tail), "content": tail}


# -----------------------
# UI pages
# -----------------------
@app.get("/", response_class=RedirectResponse)
def ui_root(request: Request) -> RedirectResponse:
    return RedirectResponse(url=request.url_for("ui_dashboard"))


@app.get("/ui", response_class=RedirectResponse)
def ui_home(request: Request) -> RedirectResponse:
    return RedirectResponse(url=request.url_for("ui_dashboard"))


@app.get("/ui/dashboard", response_class=HTMLResponse)
def ui_dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("dashboard.html", {"request": request, "page": "dashboard"})


@app.get("/ui/config", response_class=HTMLResponse)
def ui_config(request: Request) -> HTMLResponse:
    cfg_text = ""
    if config_store:
        try:
            cfg_text = json.dumps(config_store.read(reload=False), indent=2, ensure_ascii=False)
        except Exception:
            cfg_text = ""
    return templates.TemplateResponse(
        "config.html",
        {"request": request, "page": "config", "config_json": cfg_text},
    )


@app.get("/ui/logs", response_class=HTMLResponse)
def ui_logs(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("logs.html", {"request": request, "page": "logs"})
