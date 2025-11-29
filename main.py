from __future__ import annotations

import argparse
import asyncio
import logging
from typing import Any

import uvicorn

from acs_manager.capture.sniffer import PacketSniffer
from acs_manager.config.loader import load_settings
from acs_manager.management.controller import ContainerManager
from acs_manager.webui import app as web_app


async def start_web_ui(web_cfg: dict[str, Any]) -> None:
    host = web_cfg.get("host", "0.0.0.0")
    port = int(web_cfg.get("port", 8000))
    log_level = web_cfg.get("log_level", "info")
    config = uvicorn.Config(web_app.app, host=host, port=port, log_level=log_level)
    server = uvicorn.Server(config)
    await server.serve()


async def run(config_path: str) -> None:
    settings = load_settings(config_path)
    manager = ContainerManager(settings)
    web_app.bind_manager(manager)

    async def on_new_ip(ip: str) -> None:
        await manager.handle_new_ip(ip)

    sniffer = PacketSniffer(
        target_url=settings.get("acs", {}).get("base_url", ""),
        on_new_ip=lambda ip: asyncio.create_task(on_new_ip(ip)),
    )

    web_cfg = settings.get("webui", {})
    tasks = [asyncio.create_task(sniffer.start())]
    tasks.append(asyncio.create_task(start_web_ui(web_cfg)))
    logging.info("ACS Manager running. Press Ctrl+C to exit.")
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logging.info("Shutdown requested.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ACS Manager entrypoint")
    parser.add_argument(
        "--config",
        default="config/settings.example.yaml",
        help="Path to YAML/JSON config file",
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
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(run(args.config))
