from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException

from acs_manager.management.controller import ContainerManager

app = FastAPI(title="ACS Manager UI", version="0.1.0")

manager: Optional[ContainerManager] = None


def bind_manager(instance: ContainerManager) -> None:
    global manager
    manager = instance


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/state")
def state() -> dict:
    if manager is None:
        raise HTTPException(status_code=503, detail="Manager not wired to web UI yet")
    return manager.snapshot()
