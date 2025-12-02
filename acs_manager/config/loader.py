# -*- coding: utf-8 -*-
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

try:
    import yaml
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "PyYAML is required to load YAML config files. Install via `pip install pyyaml`."
    ) from exc


def load_settings(path: str | Path) -> Dict[str, Any]:
    """Load configuration from a YAML or JSON file."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    suffix = config_path.suffix.lower()
    if suffix in {".yml", ".yaml"}:
        with config_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}

    if suffix == ".json":
        with config_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    raise ValueError(
        f"Unsupported config format for {config_path}. Use YAML or JSON."
    )


def dump_settings(path: str | Path, data: Dict[str, Any]) -> None:
    """Persist configuration to YAML or JSON, writing atomically."""
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)

    suffix = config_path.suffix.lower()
    if suffix in {".yml", ".yaml"}:
        payload = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    elif suffix == ".json":
        payload = json.dumps(data, indent=2)
    else:
        raise ValueError(
            f"Unsupported config format for {config_path}. Use YAML or JSON."
        )

    temp_path = config_path.with_suffix(config_path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        handle.write(payload)
    temp_path.replace(config_path)


def get_section(
    settings: Dict[str, Any], key: str, default: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    """Safely pull a nested section with a default when missing."""
    value = settings.get(key, default or {})
    if not isinstance(value, dict):
        raise ValueError(f"Section `{key}` must be a mapping.")
    return value
