# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Callable, Deque, Dict, Optional

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
        self.recent_events: Deque[Dict[str, str]] = deque(maxlen=50)

    async def start(self) -> None:
        """Placeholder async loop to plug into your capture backend."""
        logger.info(
            "PacketSniffer started for %s. Wire this up to browser/network events.",
            self.target_url,
        )
        while True:
            await asyncio.sleep(1)

    def handle_event(self, payload: Dict[str, str]) -> Optional[str]:
        """
        Consume a captured event and attempt to extract a container IP.

        Args:
            payload: Parsed request/response content (headers/body/URL fields).
        """
        self.recent_events.append(payload)
        candidate = self._extract_ip(payload)
        if candidate and candidate != self.latest_ip:
            self.latest_ip = candidate
            logger.info("Captured new container IP: %s", candidate)
            if self.on_new_ip:
                self.on_new_ip(candidate)
            return candidate
        return None

    def _extract_ip(self, payload: Dict[str, str]) -> Optional[str]:
        """Naive IP extractor; replace with ACS-specific parsing rules."""
        for key in ("ip", "host", "address"):
            value = payload.get(key)
            if value and self._looks_like_ip(value):
                return value
        body = payload.get("body") or ""
        for token in body.replace("/", " ").replace("=", " ").split():
            if self._looks_like_ip(token):
                return token
        return None

    @staticmethod
    def _looks_like_ip(text: str) -> bool:
        parts = text.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
