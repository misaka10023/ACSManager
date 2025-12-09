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
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from acs_manager.config.store import ConfigStore
from acs_manager.management.controller import ContainerManager
from acs_manager.management.multi_manager import MultiContainerManager

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
        new_scope["raw_path"] = trimmed.encode()
        return await self.app(new_scope, receive, send)


@app.exception_handler(404)
async def log_404(request: Request, exc: HTTPException) -> JSONResponse:
    url_path = request.url.path
    fs_path: Optional[Path] = None

    try:
        # 还原静态文件在磁盘上的绝对路径，帮助排查工作目录/前缀问题
        root = app.root_path or ""
        if root and url_path.startswith(root + "/static"):
            rel = url_path[len(root) :].lstrip("/")
        elif url_path.startswith("/static"):
            rel = url_path.lstrip("/")
        else:
            rel = ""
        if rel.startswith("static/"):
            rel = rel[len("static/") :]
        if rel:
            fs_path = (STATIC_DIR / rel).resolve()
    except Exception:
        fs_path = None

    if fs_path is not None:
        logger.warning("404 %s %s -> fs %s (root_path=%s)", request.method, url_path, fs_path, app.root_path)
    else:
        logger.warning("404 %s %s (root_path=%s)", request.method, url_path, app.root_path)

    # Mirror default 404 response shape
    detail = exc.detail if isinstance(exc, HTTPException) else "Not Found"
    return JSONResponse(status_code=404, content={"detail": detail})

templates = Jinja2Templates(directory=TEMPLATES_DIR)

manager: Optional[ContainerManager] = None
multi_manager: Optional[MultiContainerManager] = None
config_store: Optional[ConfigStore] = None
LOG_DIR = Path("logs")
_root_path_middleware_added = False
SESSION_COOKIE = "acsui_session"
DEFAULT_SECRET = "change-me-please"


def bind_manager(instance: ContainerManager) -> None:
    global manager
    manager = instance


def bind_multi_manager(instance: MultiContainerManager) -> None:
    global multi_manager
    multi_manager = instance


def bind_config_store(store: ConfigStore) -> None:
    global config_store
    config_store = store


def _resolve_manager(container_id: Optional[str] = None) -> Optional[ContainerManager]:
    if multi_manager:
        if container_id:
            return multi_manager.get_manager(container_id)
        # default: first manager
        for mgr in multi_manager.managers.values():  # type: ignore[attr-defined]
            return mgr
        return None
    return manager


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


@app.get("/static/{path:path}", name="static")
async def static_files(path: str, request: Request) -> Response:
    """
    Serve static assets from STATIC_DIR, respecting root_path via middleware.
    """
    # 防止路径穿越
    rel_path = Path(path)
    full_path = (STATIC_DIR / rel_path).resolve()
    try:
        static_root = STATIC_DIR.resolve()
    except Exception:
        static_root = STATIC_DIR
    if not str(full_path).startswith(str(static_root)):
        logger.warning("Blocked static path traversal: %s -> %s", request.url.path, full_path)
        raise HTTPException(status_code=404, detail="Not Found")
    if not full_path.is_file():
        logger.warning("Static file not found: %s -> %s", request.url.path, full_path)
        raise HTTPException(status_code=404, detail="Not Found")
    return Response(full_path.read_bytes(), media_type=None)


@app.get("/state")
def state(
    container_id: Optional[str] = Query(None),
    user: str = Depends(require_auth),
) -> dict:
    mgr = _resolve_manager(container_id)
    if mgr is None:
        raise HTTPException(status_code=503, detail="Manager not wired to web UI yet")
    return mgr.snapshot()


@app.get("/containers")
def list_containers(user: str = Depends(require_auth)) -> list[dict]:
    if multi_manager:
        return multi_manager.list_states()
    if manager:
        return [manager.snapshot()]
    raise HTTPException(status_code=503, detail="Manager not wired to web UI yet")


@app.get("/container-ip")
def container_ip(container_id: Optional[str] = Query(None)) -> dict:
    mgr = _resolve_manager(container_id)
    if mgr is None:
        raise HTTPException(status_code=503, detail="Manager not wired to web UI yet")
    ip = mgr.snapshot().get("container_ip")
    source = "captured"
    if not ip:
        try:
            ip = mgr.resolve_container_ip(force_login=True)
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
    if mgr and mgr.snapshot().get("last_seen"):
        seen = mgr.snapshot().get("last_seen")
        if isinstance(seen, dt.datetime):
            payload["updated_at"] = seen.strftime("%Y-%m-%d %H:%M:%S")
    return payload


@app.post("/containers/{container_id}/restart")
async def restart_tunnel(container_id: str, user: str = Depends(require_auth)) -> dict:
    mgr = _resolve_manager(container_id)
    if mgr is None:
        raise HTTPException(status_code=404, detail="Container not found")
    await mgr.restart_tunnel()
    return {"status": "restarted"}


@app.post("/containers/{container_id}/start")
async def start_tunnel(container_id: str, user: str = Depends(require_auth)) -> dict:
    mgr = _resolve_manager(container_id)
    if mgr is None:
        raise HTTPException(status_code=404, detail="Container not found")
    await mgr.start_tunnel()
    return {"status": "started"}


@app.post("/containers/{container_id}/stop")
async def stop_tunnel(container_id: str, user: str = Depends(require_auth)) -> dict:
    mgr = _resolve_manager(container_id)
    if mgr is None:
        raise HTTPException(status_code=404, detail="Container not found")
    await mgr.stop_tunnel()
    return {"status": "stopped"}


@app.post("/containers/{container_id}/refresh-ip")
def refresh_ip(container_id: str, user: str = Depends(require_auth)) -> dict:
    mgr = _resolve_manager(container_id)
    if mgr is None:
        raise HTTPException(status_code=404, detail="Container not found")
    ip = mgr.resolve_container_ip(force_login=True)
    return {"ip": ip, "container_ip": ip}


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
    """Handle config changes: restart tunnels (all containers when multi)."""
    targets: list[ContainerManager] = []
    if multi_manager:
        targets = list(multi_manager.managers.values())
    elif manager:
        targets = [manager]
    else:
        return

    if "containers" in new_cfg:
        for mgr in targets:
            try:
                await mgr.restart_tunnel()
            except Exception as exc:
                logger.error("Failed to restart tunnel (%s): %s", getattr(mgr, "container_id", "unknown"), exc)
        return

    before = _critical_snapshot(old_cfg)
    after = _critical_snapshot(new_cfg)

    acs_keys = [k for k in before.keys() if k.startswith("acs.")]
    ssh_keys = [k for k in before.keys() if k.startswith("ssh.")]

    acs_changed = any(before[k] != after[k] for k in acs_keys)
    ssh_changed = any(before[k] != after[k] for k in ssh_keys)

    if acs_changed:
        for mgr in targets:
            try:
                logger.info("ACS config changed; re-login to refresh cookies.")
                mgr.container_client.login()  # type: ignore[attr-defined]
            except Exception as exc:  # pragma: no cover
                logger.error("Failed to refresh ACS cookies (%s): %s", getattr(mgr, "container_id", "unknown"), exc)

    if ssh_changed:
        for mgr in targets:
            try:
                logger.info("SSH config changed; restarting tunnel.")
                await mgr.restart_tunnel()
            except Exception as exc:  # pragma: no cover
                logger.error("Failed to restart SSH tunnel (%s): %s", getattr(mgr, "container_id", "unknown"), exc)


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
        {
            "request": request,
            "page": "login",
            "error": "",
            "auth_enabled": auth_cfg.get("enabled"),
            "is_authenticated": False,
        },
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
        {
            "request": request,
            "page": "login",
            "error": "用户名或密码错误",
            "auth_enabled": auth_cfg.get("enabled"),
            "is_authenticated": False,
        },
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
        {
            "request": request,
            "page": "dashboard",
            "auth_enabled": auth_cfg.get("enabled"),
            "is_authenticated": bool(_current_user(request, auth_cfg)),
        },
    )


@app.get("/ui/config", response_class=HTMLResponse)
def ui_config(request: Request) -> HTMLResponse:
    auth_cfg = _auth_settings()
    redirect = _maybe_redirect_login(request, auth_cfg)
    if redirect:
        return redirect
    cfg_text = ""
    template_text = ""
    example_path = BASE_DIR.parent.parent / "config" / "examples" / "settings.example.yaml"
    if config_store:
        try:
            cfg_text = json.dumps(config_store.read(reload=False), indent=2, ensure_ascii=False)
        except Exception:
            cfg_text = ""
    try:
        template_text = example_path.read_text(encoding="utf-8")
    except Exception:
        template_text = ""
    return templates.TemplateResponse(
        "config.html",
        {
            "request": request,
            "page": "config",
            "config_json": cfg_text,
            "config_template": template_text,
            "auth_enabled": auth_cfg.get("enabled"),
            "is_authenticated": bool(_current_user(request, auth_cfg)),
        },
    )


@app.get("/ui/logs", response_class=HTMLResponse)
def ui_logs(request: Request) -> HTMLResponse:
    auth_cfg = _auth_settings()
    redirect = _maybe_redirect_login(request, auth_cfg)
    if redirect:
        return redirect
    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "page": "logs",
            "auth_enabled": auth_cfg.get("enabled"),
            "is_authenticated": bool(_current_user(request, auth_cfg)),
        },
    )
