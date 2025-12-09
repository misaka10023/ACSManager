# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import logging
import shutil
from pathlib import Path
from typing import Any, Dict, List

import uvicorn

from acs_manager.capture.sniffer import PacketSniffer
from acs_manager.config import ConfigStore
from acs_manager.management.multi_manager import MultiContainerManager
from acs_manager.webui import app as web_app

DEFAULT_CONFIG = "config/local/settings.yaml"
TEMPLATE_CONFIG = "config/examples/settings.example.yaml"


async def start_web_ui(web_cfg: dict[str, Any]) -> None:
    host = web_cfg.get("host", "0.0.0.0")
    port = int(web_cfg.get("port", 8000))
    log_level = web_cfg.get("log_level", "info")
    config = uvicorn.Config(
        web_app.app,
        host=host,
        port=port,
        log_level=log_level,
    )
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


def ensure_config(config_path: str, template_path: str = TEMPLATE_CONFIG) -> tuple[Path, bool]:
    """
    Ensure the target config exists; if missing, create directories and copy from template.
    """
    target = Path(config_path)
    if target.exists():
        return target, False
    template = Path(template_path)
    if not template.exists():
        raise FileNotFoundError(f"Config template not found: {template}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(template, target)
    return target, True


async def run(config_path: str, log_level: str) -> None:
    cfg_path, created = ensure_config(config_path)
    if created:
        logging.error("已生成配置文件 %s，请填写配置后重新运行。", cfg_path)
        return
    store = ConfigStore(cfg_path)
    multi_manager = MultiContainerManager(store)
    multi_manager.init_managers()
    web_app.bind_multi_manager(multi_manager)
    web_app.bind_config_store(store)

    web_cfg = store.get_section("webui", default={}, reload=True)
    web_app.set_root_path(web_cfg.get("root_path", ""))

    web_task = asyncio.create_task(start_web_ui(web_cfg))
    background_tasks = await multi_manager.start_background_tasks()

    sniffer_tasks = []
    for m in multi_manager.managers.values():
        try:
            acs_cfg = m._acs_cfg(reload=True)  # type: ignore[attr-defined]
            target_url = acs_cfg.get("base_url", "")
            if target_url:
                sniffer = PacketSniffer(
                    target_url=target_url,
                    on_new_ip=lambda ip, mgr=m: asyncio.create_task(mgr.handle_new_ip(ip)),
                )
                sniffer_tasks.append(asyncio.create_task(sniffer.start()))
        except Exception as exc:
            logging.warning("Failed to start sniffer for %s: %s", getattr(m, "container_id", "unknown"), exc)

    tasks = sniffer_tasks + [web_task] + background_tasks
    logging.info("ACS Manager running. Press Ctrl+C to exit.")
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logging.info("Shutdown requested.")
    finally:
        await multi_manager.shutdown()


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
