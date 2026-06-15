# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Any, Callable, Deque, Dict, Optional

from acs_manager.common.ip_utils import extract_ip as _shared_extract_ip

logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    Lightweight stub for capturing ACS web traffic.

    Integrate this with your preferred tooling (DevTools protocol, playwright,
    mitmproxy, etc.) and forward parsed request/response bodies to
    ``handle_event`` so the manager can discover new container IPs.
    """

    def __init__(
        self,
        *,
        target_url: str,
        on_new_ip: Callable[[str], None] | None = None,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.on_new_ip = on_new_ip
        self.latest_ip: Optional[str] = None
        self.recent_events: Deque[Dict[str, Any]] = deque(maxlen=50)

    async def start(self) -> None:
        """Placeholder async loop to plug into your capture backend."""
        logger.info(
            "PacketSniffer started for %s. Wire this up to browser/network events.",
            self.target_url,
        )
        while True:
            await asyncio.sleep(1)

    def handle_event(self, payload: Dict[str, Any]) -> Optional[str]:
        """
        Consume a captured event and attempt to extract a container IP.

        Args:
            payload: Parsed request/response content (headers/body/URL fields).
        """
        self.recent_events.append(payload)
        candidate = self.extract_ip(payload)
        if candidate and candidate != self.latest_ip:
            self.latest_ip = candidate
            logger.info("Captured new container IP: %s", candidate)
            if self.on_new_ip:
                self.on_new_ip(candidate)
            return candidate
        return None

    @classmethod
    def extract_ip(cls, payload: Any) -> Optional[str]:
        """Extract an IP from ACS API payloads, captured bodies, or loose text."""
        return _shared_extract_ip(payload)
