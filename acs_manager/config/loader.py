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


def get_section(settings: Dict[str, Any], key: str, default: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Safely pull a nested section with a default when missing."""
    value = settings.get(key, default or {})
    if not isinstance(value, dict):
        raise ValueError(f"Section `{key}` must be a mapping.")
    return value
