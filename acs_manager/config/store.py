# -*- coding: utf-8 -*-
from __future__ import annotations

import copy
import logging
import shutil
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from acs_manager.config.loader import dump_settings, get_section, load_settings

logger = logging.getLogger(__name__)


class ConfigStore:
    """
    Thread-safe config cache with reload/read/update helpers.
    Allows the running app and Web UI to read and persist the latest settings.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        template_path: Optional[str | Path] = None,
        backup_dir: Optional[str | Path] = None,
    ) -> None:
        self.path = Path(path)
        self._template_path = self._resolve_template_path(template_path)
        self._backup_dir = self._resolve_backup_dir(backup_dir)
        self._lock = threading.RLock()
        self._cache: Dict[str, Any] = {}
        self._format = self.path.suffix.lower()
        self._migration_performed = False
        self._migration_backup: Optional[Path] = None
        self._template_version: Optional[Any] = self._load_template_version()
        self._ensure_version()
        self.reload()

    def _resolve_template_path(self, template_path: Optional[str | Path]) -> Optional[Path]:
        if template_path:
            candidate = Path(template_path)
            return candidate if candidate.exists() else None

        # Try relative to the config root (config/examples/settings.example.yaml)
        candidates = [
            self.path.parent.parent / "examples" / "settings.example.yaml",
            Path("config") / "examples" / "settings.example.yaml",
            Path(__file__).resolve().parent.parent / "config" / "examples" / "settings.example.yaml",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    def _load_template_version(self) -> Optional[Any]:
        if not self._template_path or not self._template_path.exists():
            return None
        try:
            cfg = load_settings(self._template_path)
            return (cfg or {}).get("config_version")
        except Exception as exc:
            logger.warning("Failed to load template config %s for version: %s", self._template_path, exc)
            return None

    def _resolve_backup_dir(self, backup_dir: Optional[str | Path]) -> Path:
        if backup_dir:
            return Path(backup_dir)
        root_dir = self.path.parent
        # config/local -> config/old
        if root_dir.name.lower() in {"local", "dev", "prod"} and root_dir.parent.exists():
            root_dir = root_dir.parent
        return root_dir / "old"

    def _backup_current(self) -> Optional[Path]:
        if not self.path.exists():
            return None
        backup_dir = self._backup_dir
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / f"{self.path.name}.old"
        try:
            shutil.copy2(self.path, backup_path)
            logger.info("Backed up config to %s", backup_path)
            return backup_path
        except Exception as exc:
            logger.warning("Failed to back up config to %s: %s", backup_path, exc)
            return None

    def _merge_with_template(self, template: Any, current: Any) -> Any:
        """
        Merge user values from `current` into `template` shape.
        - Dict: only overlay keys that exist in template (including config_version).
        - List: prefer current list entirely when types match.
        - Scalar: prefer current when types match; otherwise keep template.
        """
        if isinstance(template, dict) and isinstance(current, dict):
            merged = copy.deepcopy(template)
            for key, value in merged.items():
                if key in current:
                    merged[key] = self._merge_with_template(value, current[key])
            return merged
        if isinstance(template, list) and isinstance(current, list):
            return type(template)(current)
        if type(template) is type(current):
            return current
        return template

    def _ensure_version(self) -> None:
        """
        If config version is missing or mismatched against the template,
        back up the current file to ./config/old/<name>.old, regenerate from
        template, and re-apply user values.
        """
        if not self._template_path or not self._template_path.exists():
            return

        try:
            template_cfg = load_settings(self._template_path)
        except Exception as exc:
            logger.warning("Failed to load template config %s: %s", self._template_path, exc)
            return

        template_version = (template_cfg or {}).get("config_version")
        self._template_version = template_version
        if template_version is None:
            return

        if not self.path.exists():
            return

        try:
            current_cfg = load_settings(self.path)
        except Exception as exc:
            logger.warning("Failed to load current config %s: %s", self.path, exc)
            return

        current_version = (current_cfg or {}).get("config_version")
        if current_version == template_version:
            return

        backup_path = self._backup_current()
        merged = self._merge_with_template(copy.deepcopy(template_cfg), current_cfg)
        merged["config_version"] = template_version
        try:
            dump_settings(self.path, merged)
            self._migration_performed = True
            self._migration_backup = backup_path
            logger.info(
                "Migrated config %s from version %s to %s using template %s",
                self.path,
                current_version,
                template_version,
                self._template_path,
            )
        except Exception as exc:
            logger.warning("Failed to write migrated config %s: %s", self.path, exc)

    def _inject_version(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(data, dict):
            return data
        target_version = data.get("config_version")
        if target_version is None and isinstance(self._cache, dict):
            target_version = self._cache.get("config_version")
        if target_version is None:
            target_version = self._template_version
        if target_version is None:
            return data
        updated = copy.deepcopy(data)
        updated["config_version"] = target_version
        return updated

    @property
    def migration_performed(self) -> bool:
        return bool(self._migration_performed)

    @property
    def migration_backup(self) -> Optional[Path]:
        return self._migration_backup

    def reload(self) -> Dict[str, Any]:
        """Force reload from disk and refresh the cache."""
        with self._lock:
            self._cache = load_settings(self.path)
            return copy.deepcopy(self._cache)

    def read(self, *, reload: bool = False) -> Dict[str, Any]:
        """Return the cached config, optionally reloading from disk first."""
        with self._lock:
            if reload or self._cache is None:
                self._cache = load_settings(self.path)
            return copy.deepcopy(self._cache)

    def get_section(
        self,
        key: str,
        default: Dict[str, Any] | None = None,
        *,
        reload: bool = False,
    ) -> Dict[str, Any]:
        """Convenience to fetch a mapping section with validation."""
        return get_section(self.read(reload=reload), key, default)

    def write(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace the entire config and persist to disk."""
        with self._lock:
            payload = copy.deepcopy(data)
            payload = self._inject_version(payload)
            self._cache = payload
            dump_settings(self.path, self._cache)
            return copy.deepcopy(self._cache)

    def update(self, changes: Dict[str, Any]) -> Dict[str, Any]:
        """Shallow-merge changes into the config and persist."""
        with self._lock:
            merged = copy.deepcopy(self._cache)
            if merged is None:
                merged = {}
            merged.update(changes)
            merged = self._inject_version(merged)
            self._cache = merged
            dump_settings(self.path, self._cache)
            return copy.deepcopy(self._cache)

    def format(self) -> str:
        return self._format
