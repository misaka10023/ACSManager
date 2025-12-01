from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import logging
import shutil
from pathlib import Path
from typing import Any

import uvicorn

from acs_manager.capture.sniffer import PacketSniffer
from acs_manager.config import ConfigStore
from acs_manager.management.controller import ContainerManager
from acs_manager.webui import app as web_app

DEFAULT_CONFIG = "config/local/settings.yaml"
TEMPLATE_CONFIG = "config/examples/settings.example.yaml"


async def start_web_ui(web_cfg: dict[str, Any]) -> None:
    host = web_cfg.get("host", "0.0.0.0")
    port = int(web_cfg.get("port", 8000))
    log_level = web_cfg.get("log_level", "info")
    config = uvicorn.Config(web_app.app, host=host, port=port, log_level=log_level)
    server = uvicorn.Server(config)
    await server.serve()


def setup_logging(log_level: str) -> Path:
    """Configure logging to console + daily file under ./logs/YYYY-MM-DD.log."""
    log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{dt.date.today()}.log"
    handlers = [
        logging.FileHandler(log_path, encoding="utf-8"),
        logging.StreamHandler(),
    ]
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )
    return log_path


def ensure_config(config_path: str, template_path: str = TEMPLATE_CONFIG) -> Path:
    """
    Ensure the target config exists; if missing, create directories and copy from template.
    """
    target = Path(config_path)
    if target.exists():
        return target
    template = Path(template_path)
    if not template.exists():
        raise FileNotFoundError(f"Config template not found: {template}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(template, target)
    return target


async def run(config_path: str, log_level: str) -> None:
    cfg_path = ensure_config(config_path)
    store = ConfigStore(cfg_path)
    manager = ContainerManager(store)
    web_app.bind_manager(manager)
    web_app.bind_config_store(store)

    async def on_new_ip(ip: str) -> None:
        await manager.handle_new_ip(ip)

    acs_cfg = store.get_section("acs", default={}, reload=True)
    sniffer = PacketSniffer(
        target_url=acs_cfg.get("base_url", ""),
        on_new_ip=lambda ip: asyncio.create_task(on_new_ip(ip)),
    )

    web_cfg = store.get_section("webui", default={}, reload=True)
    tasks = [
        asyncio.create_task(sniffer.start()),
        asyncio.create_task(start_web_ui(web_cfg)),
        asyncio.create_task(manager.maintain_tunnel()),
    ]
    # monitor container status/near-shutdown restarts
    if acs_cfg.get("container_name"):
        tasks.append(
            asyncio.create_task(
                manager.monitor_container(pre_shutdown_minutes=10, slow_interval=300, fast_interval=30)
            )
        )
    logging.info("ACS Manager running. Press Ctrl+C to exit.")
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logging.info("Shutdown requested.")
    finally:
        await manager.shutdown()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ACS Manager entrypoint")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help="Path to YAML/JSON config file (auto-created from template if missing)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    log_path = setup_logging(args.log_level)
    logging.info("Log file: %s", log_path)
    asyncio.run(run(args.config, args.log_level))
