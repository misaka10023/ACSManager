# -*- coding: utf-8 -*-
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

try:
    from ruamel.yaml import YAML
    _yaml_rt = YAML(typ="rt")
    _yaml_rt.preserve_quotes = True
    _yaml_rt.indent(mapping=2, sequence=4, offset=2)
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "ruamel.yaml is required to load YAML config files with comments preserved. Install via `pip install ruamel.yaml`."
    ) from exc


def load_settings(path: str | Path) -> Dict[str, Any]:
    """Load configuration from a YAML or JSON file."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    suffix = config_path.suffix.lower()
    if suffix in {".yml", ".yaml"}:
        with config_path.open("r", encoding="utf-8") as handle:
            return _yaml_rt.load(handle) or {}

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
        temp_path = config_path.with_suffix(config_path.suffix + ".tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            _yaml_rt.dump(data, handle)
        temp_path.replace(config_path)
        return

    if suffix == ".json":
        payload = json.dumps(data, indent=2)
        temp_path = config_path.with_suffix(config_path.suffix + ".tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            handle.write(payload)
        temp_path.replace(config_path)
        return

    raise ValueError(
        f"Unsupported config format for {config_path}. Use YAML or JSON."
    )


def get_section(
    settings: Dict[str, Any], key: str, default: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    """Safely pull a nested section with a default when missing."""
    value = settings.get(key, default or {})
    if not isinstance(value, dict):
        raise ValueError(f"Section `{key}` must be a mapping.")
    return value
