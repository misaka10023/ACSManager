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
    """Landing page: 显示健康、状态、IP、配置、日志。"""
    html = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head><meta charset="UTF-8"><title>ACS Manager</title></head>
    <body>
      <h2>ACS Manager Web UI</h2>
      <div id="sections">
        <section>
          <h3>健康</h3>
          <pre id="health"></pre>
        </section>
        <section>
          <h3>运行状态</h3>
          <pre id="state"></pre>
        </section>
        <section>
          <h3>容器 IP</h3>
          <pre id="cip"></pre>
        </section>
        <section>
          <h3>最新日志（200行）</h3>
          <pre id="logs"></pre>
        </section>
      </div>
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
        async function loadHealth() {
          const res = await fetch('/health');
          document.getElementById('health').textContent = JSON.stringify(await res.json(), null, 2);
        }
        async function loadState() {
          const res = await fetch('/state');
          document.getElementById('state').textContent = JSON.stringify(await res.json(), null, 2);
        }
        async function loadIP() {
          try {
            const res = await fetch('/container-ip');
            document.getElementById('cip').textContent = JSON.stringify(await res.json(), null, 2);
          } catch (e) {
            document.getElementById('cip').textContent = e.toString();
          }
        }
        async function loadLogs() {
          try {
            const res = await fetch('/logs');
            document.getElementById('logs').textContent = JSON.stringify(await res.json(), null, 2);
          } catch (e) {
            document.getElementById('logs').textContent = e.toString();
          }
        }
        async function refreshAll() {
          await Promise.all([loadHealth(), loadState(), loadIP(), loadCfg(), loadLogs()]);
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
            await refreshAll();
          } catch (e) {
            document.getElementById('msg').textContent = e.toString();
          }
        }
        refreshAll();
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
                return {"container_ip": fallback, "source": "fallback"}
        if not ip:
            raise HTTPException(status_code=404, detail="Container IP not available yet")
    return {"container_ip": ip, "source": source}


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
