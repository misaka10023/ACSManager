# -*- coding: utf-8 -*-
"""IP extraction helpers shared across capture and container modules."""
from __future__ import annotations

import json
from typing import Any, Optional

__all__ = ["extract_ip", "looks_like_ip"]


def looks_like_ip(text: str) -> bool:
    """Return True if ``text`` parses as a dotted-quad IPv4 address."""
    parts = text.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def extract_ip(payload: Any) -> Optional[str]:
    """Extract an IP from ACS API payloads, captured bodies, or loose text."""
    if isinstance(payload, dict):
        for key in ("instanceIp", "headerNotebookIp", "container_ip", "ip", "host", "address"):
            if key not in payload:
                continue
            candidate = extract_ip(payload.get(key))
            if candidate:
                return candidate
        for value in payload.values():
            candidate = extract_ip(value)
            if candidate:
                return candidate
        return None

    if isinstance(payload, (list, tuple)):
        for item in payload:
            candidate = extract_ip(item)
            if candidate:
                return candidate
        return None

    if not isinstance(payload, str):
        return None

    text = payload.strip()
    if not text:
        return None
    if looks_like_ip(text):
        return text

    if text[:1] in "{[":
        try:
            candidate = extract_ip(json.loads(text))
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
        if looks_like_ip(token):
            return token
    return None
