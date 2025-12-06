# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Body, Depends, FastAPI, Form, HTTPException, Query, Request, Response
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
        new_scope["path"] = path[len(self.prefix) :] or "/"
        return await self.app(new_scope, receive, send)

# mount static assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

manager: Optional[ContainerManager] = None
config_store: Optional[ConfigStore] = None
LOG_DIR = Path("logs")
_root_path_middleware_added = False
SESSION_COOKIE = "acsui_session"
DEFAULT_SECRET = "change-me-please"


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


def _auth_settings(reload: bool = False) -> Dict[str, Any]:
    defaults = {
        "enabled": False,
        "username": "",
        "password": "",
        "password_hash": "",
        "secret_key": DEFAULT_SECRET,
        "session_ttl": 60 * 60 * 12,  # 12h
    }
    if config_store:
        try:
            webui_cfg = config_store.get_section("webui", default={}, reload=reload)
            auth_cfg = (webui_cfg.get("auth") or {}) if isinstance(webui_cfg, dict) else {}
            defaults.update(
                {
                    "enabled": bool(auth_cfg.get("enabled")),
                    "username": auth_cfg.get("username", ""),
                    "password": auth_cfg.get("password", ""),
                    "password_hash": auth_cfg.get("password_hash", ""),
                    "secret_key": auth_cfg.get("secret_key", DEFAULT_SECRET),
                    "session_ttl": int(auth_cfg.get("session_ttl", defaults["session_ttl"])),
                }
            )
        except Exception as exc:
            logger.warning("Failed to load auth config: %s", exc)
    return defaults


def _verify_password(input_pw: str, auth_cfg: Dict[str, Any]) -> bool:
    stored_hash = (auth_cfg.get("password_hash") or "").strip()
    stored_pw = (auth_cfg.get("password") or "").strip()
    if stored_hash:
        digest = hashlib.sha256(input_pw.encode("utf-8")).hexdigest()
        return hmac.compare_digest(digest, stored_hash)
    if stored_pw:
        return hmac.compare_digest(stored_pw, input_pw)
    return False


def _sign_session(username: str, secret_key: str, ttl_seconds: int) -> str:
    expires_at = int(time.time()) + int(ttl_seconds)
    payload = f"{username}:{expires_at}"
    sig = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    token = f"{payload}:{sig}"
    return base64.urlsafe_b64encode(token.encode("utf-8")).decode("ascii")


def _decode_session(token: str, secret_key: str) -> Optional[str]:
    if not token:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        username, exp_str, sig = raw.split(":", 2)
        expected_sig = hmac.new(secret_key.encode("utf-8"), f"{username}:{exp_str}".encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        if int(exp_str) < int(time.time()):
            return None
        return username
    except Exception:
        return None


def _current_user(request: Request, auth_cfg: Dict[str, Any]) -> Optional[str]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return _decode_session(token, auth_cfg.get("secret_key", DEFAULT_SECRET))


def require_auth(request: Request) -> str:
    auth_cfg = _auth_settings(reload=False)
    if not auth_cfg.get("enabled"):
        return ""
    user = _current_user(request, auth_cfg)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user


def _maybe_redirect_login(request: Request, auth_cfg: Dict[str, Any]) -> Optional[RedirectResponse]:
    if not auth_cfg.get("enabled"):
        return None
    user = _current_user(request, auth_cfg)
    if user:
        return None
    return RedirectResponse(url=request.url_for("ui_login"), status_code=303)


# -----------------------
# JSON API (unchanged)
# -----------------------
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/state")
def state(user: str = Depends(require_auth)) -> dict:
    if manager is None:
        raise HTTPException(status_code=503, detail="Manager not wired to web UI yet")
    return manager.snapshot()


@app.get("/container-ip")
def container_ip(user: str = Depends(require_auth)) -> dict:
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
def get_config(reload: bool = True, user: str = Depends(require_auth)) -> dict:
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
async def patch_config(payload: dict = Body(..., embed=False), user: str = Depends(require_auth)) -> dict:
    if config_store is None:
        raise HTTPException(status_code=503, detail="Config store not ready")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload must be an object")
    old_cfg = config_store.read(reload=False)
    new_cfg = config_store.update(payload)
    await _post_config_change(old_cfg, new_cfg)
    return new_cfg


@app.put("/config")
async def replace_config(payload: dict = Body(..., embed=False), user: str = Depends(require_auth)) -> dict:
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
def tail_logs(lines: int = Query(200, ge=1, le=2000), user: str = Depends(require_auth)) -> dict:
    """Return the tail of the latest log file."""
    try:
        log_path = _latest_log_file()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    content_lines = log_path.read_text(encoding="utf-8").splitlines()
    tail = content_lines[-lines:] if len(content_lines) > lines else content_lines
    return {"file": str(log_path), "lines": len(tail), "content": tail}


# -----------------------
# Auth pages
# -----------------------
@app.get("/ui/login", response_class=HTMLResponse)
def ui_login(request: Request) -> HTMLResponse:
    auth_cfg = _auth_settings()
    if not auth_cfg.get("enabled"):
        return RedirectResponse(url=request.url_for("ui_dashboard"))
    if _current_user(request, auth_cfg):
        return RedirectResponse(url=request.url_for("ui_dashboard"), status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "page": "login", "error": "", "auth_enabled": auth_cfg.get("enabled")},
    )


@app.post("/ui/login", response_class=HTMLResponse)
def ui_login_submit(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
) -> HTMLResponse:
    auth_cfg = _auth_settings()
    if not auth_cfg.get("enabled"):
        return RedirectResponse(url=request.url_for("ui_dashboard"), status_code=303)

    if hmac.compare_digest(username, auth_cfg.get("username", "")) and _verify_password(password, auth_cfg):
        token = _sign_session(username, auth_cfg.get("secret_key", DEFAULT_SECRET), auth_cfg.get("session_ttl", 43200))
        resp = RedirectResponse(url=request.url_for("ui_dashboard"), status_code=303)
        cookie_path = app.root_path or "/"
        resp.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            samesite="lax",
            max_age=auth_cfg.get("session_ttl", 43200),
            path=cookie_path,
        )
        return resp

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "page": "login", "error": "用户名或密码错误", "auth_enabled": auth_cfg.get("enabled")},
        status_code=401,
    )


@app.get("/ui/logout")
def ui_logout(request: Request) -> RedirectResponse:
    auth_cfg = _auth_settings()
    target = request.url_for("ui_login") if auth_cfg.get("enabled") else request.url_for("ui_dashboard")
    resp = RedirectResponse(url=target, status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path=app.root_path or "/")
    return resp


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
    auth_cfg = _auth_settings()
    redirect = _maybe_redirect_login(request, auth_cfg)
    if redirect:
        return redirect
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "page": "dashboard", "auth_enabled": auth_cfg.get("enabled")},
    )


@app.get("/ui/config", response_class=HTMLResponse)
def ui_config(request: Request) -> HTMLResponse:
    auth_cfg = _auth_settings()
    redirect = _maybe_redirect_login(request, auth_cfg)
    if redirect:
        return redirect
    cfg_text = ""
    if config_store:
        try:
            cfg_text = json.dumps(config_store.read(reload=False), indent=2, ensure_ascii=False)
        except Exception:
            cfg_text = ""
    return templates.TemplateResponse(
        "config.html",
        {"request": request, "page": "config", "config_json": cfg_text, "auth_enabled": auth_cfg.get("enabled")},
    )


@app.get("/ui/logs", response_class=HTMLResponse)
def ui_logs(request: Request) -> HTMLResponse:
    auth_cfg = _auth_settings()
    redirect = _maybe_redirect_login(request, auth_cfg)
    if redirect:
        return redirect
    return templates.TemplateResponse("logs.html", {"request": request, "page": "logs", "auth_enabled": auth_cfg.get("enabled")})
