from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Optional

import json
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from acs_manager.config.store import ConfigStore
from acs_manager.management.controller import ContainerManager

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="ACS Manager UI", version="0.2.0")

# mount static assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

manager: Optional[ContainerManager] = None
config_store: Optional[ConfigStore] = None
LOG_DIR = Path("logs")


def bind_manager(instance: ContainerManager) -> None:
    global manager
    manager = instance


def bind_config_store(store: ConfigStore) -> None:
    global config_store
    config_store = store


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
            payload["updated_at"] = seen.isoformat()
    return payload


@app.get("/config")
def get_config(reload: bool = True) -> dict:
    if config_store is None:
        raise HTTPException(status_code=503, detail="Config store not ready")
    return config_store.read(reload=reload)


@app.patch("/config")
def patch_config(payload: dict = Body(..., embed=False)) -> dict:
    if config_store is None:
        raise HTTPException(status_code=503, detail="Config store not ready")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload must be an object")
    return config_store.update(payload)


@app.put("/config")
def replace_config(payload: dict = Body(..., embed=False)) -> dict:
    if config_store is None:
        raise HTTPException(status_code=503, detail="Config store not ready")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload must be an object")
    return config_store.write(payload)


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
def ui_root() -> RedirectResponse:
    return RedirectResponse(url="/ui/dashboard")


@app.get("/ui", response_class=RedirectResponse)
def ui_home() -> RedirectResponse:
    return RedirectResponse(url="/ui/dashboard")


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
