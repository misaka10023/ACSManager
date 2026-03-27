# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from typing import Any, Callable, Deque, Dict, Optional

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
        if isinstance(payload, dict):
            for key in ("instanceIp", "headerNotebookIp", "container_ip", "ip", "host", "address"):
                if key not in payload:
                    continue
                candidate = cls.extract_ip(payload.get(key))
                if candidate:
                    return candidate
            for value in payload.values():
                candidate = cls.extract_ip(value)
                if candidate:
                    return candidate
            return None

        if isinstance(payload, (list, tuple)):
            for item in payload:
                candidate = cls.extract_ip(item)
                if candidate:
                    return candidate
            return None

        if not isinstance(payload, str):
            return None

        text = payload.strip()
        if not text:
            return None
        if cls._looks_like_ip(text):
            return text

        if text[:1] in "{[":
            try:
                candidate = cls.extract_ip(json.loads(text))
                if candidate:
                    return candidate
            except Exception:
                pass

        normalized = (
            text.replace("/", " ")
            .replace("\\", " ")
            .replace("=", " ")
            .replace(":", " ")
            .replace(",", " ")
            .replace('"', " ")
            .replace("'", " ")
            .replace("(", " ")
            .replace(")", " ")
        )
        for token in normalized.split():
            if cls._looks_like_ip(token):
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
