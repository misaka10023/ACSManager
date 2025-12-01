from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

from acs_manager.config.store import ConfigStore
from acs_manager.management.controller import ContainerManager

app = FastAPI(title="ACS Manager UI", version="0.1.0")

manager: Optional[ContainerManager] = None
config_store: Optional[ConfigStore] = None
LOG_DIR = Path("logs")


def bind_manager(instance: ContainerManager) -> None:
    global manager
    manager = instance


def bind_config_store(store: ConfigStore) -> None:
    global config_store
    config_store = store


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/state")
def state() -> dict:
    if manager is None:
        raise HTTPException(status_code=503, detail="Manager not wired to web UI yet")
    return manager.snapshot()


@app.get("/")
def root() -> HTMLResponse:
    """Simple UI landing page."""
    html = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head><meta charset="UTF-8"><title>ACS Manager</title></head>
    <body>
      <h2>ACS Manager Web UI</h2>
      <p><a href="/health" target="_blank">/health</a></p>
      <p><a href="/state" target="_blank">/state</a></p>
      <p><a href="/config" target="_blank">GET /config</a></p>
      <p><a href="/logs" target="_blank">GET /logs</a></p>
      <h3>配置修改</h3>
      <form id="cfgForm">
        <textarea id="cfg" rows="20" cols="80"></textarea><br/>
        <button type="button" onclick="save()">保存 (PUT /config)</button>
      </form>
      <pre id="msg"></pre>
      <script>
        async function loadCfg() {
          const res = await fetch('/config');
          const data = await res.json();
          document.getElementById('cfg').value = JSON.stringify(data, null, 2);
        }
        async function save() {
          const txt = document.getElementById('cfg').value;
          try {
            const json = JSON.parse(txt);
            const res = await fetch('/config', {
              method: 'PUT',
              headers: {'Content-Type':'application/json'},
              body: JSON.stringify(json)
            });
            const data = await res.json();
            document.getElementById('msg').textContent = JSON.stringify(data, null, 2);
          } catch (e) {
            document.getElementById('msg').textContent = e.toString();
          }
        }
        loadCfg();
      </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/container-ip")
def container_ip() -> dict:
    if manager is None:
        raise HTTPException(status_code=503, detail="Manager not wired to web UI yet")
    ip = manager.snapshot().get("container_ip")
    if not ip:
        # 灏濊瘯鐢ㄩ厤缃腑鐨勫洖閫€鍊?        fallback = None
        if config_store:
            settings = config_store.read(reload=True)
            fallback = (
                settings.get("ssh", {}).get("container_ip")
                or settings.get("acs", {}).get("container_ip_hint")
            )
        if not fallback:
            raise HTTPException(status_code=404, detail="Container IP not available yet")
        return {"container_ip": fallback, "source": "fallback"}
    return {"container_ip": ip, "source": "captured"}


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
