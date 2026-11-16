"""Configuration loading (TOML). Command-line flags override the config file, which overrides defaults."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

DEFAULT_CONFIG_PATHS = ["./homeguard.toml", "~/.config/homeguard/config.toml"]


@dataclass
class Config:
    output_dir: str = "reports"
    formats: List[str] = field(default_factory=lambda: ["md", "html"])
    fail_on: str = "high"

    local_enabled: bool = True
    min_macos_major: int = 15
    check_pending_updates: bool = False

    network_enabled: bool = False
    targets: List[str] = field(default_factory=list)
    authorized_networks: List[str] = field(default_factory=list)
    timeout: float = 0.6
    workers: int = 128
    max_hosts: int = 1024
    extra_ports: List[int] = field(default_factory=list)
    resolve_names: bool = True

    deps_enabled: bool = False
    deps_paths: List[str] = field(default_factory=list)
    offline: bool = False
    osv_url: str = "https://api.osv.dev"

    source: Optional[str] = None


class ConfigError(ValueError):
    pass


_MAPPING = {
    "general": {"output_dir": "output_dir", "formats": "formats", "fail_on": "fail_on"},
    "local": {
        "enabled": "local_enabled",
        "min_macos_major": "min_macos_major",
        "check_pending_updates": "check_pending_updates",
    },
    "network": {
        "enabled": "network_enabled",
        "targets": "targets",
        "authorized_networks": "authorized_networks",
        "timeout": "timeout",
        "workers": "workers",
        "max_hosts": "max_hosts",
        "extra_ports": "extra_ports",
        "resolve_names": "resolve_names",
    },
    "deps": {"enabled": "deps_enabled", "paths": "paths_", "offline": "offline", "osv_url": "osv_url"},
}


def from_dict(data: Dict[str, Any], source: Optional[str] = None) -> Config:
    cfg = Config(source=source)
    for section, keys in _MAPPING.items():
        sec = data.get(section) or {}
        if not isinstance(sec, dict):
            raise ConfigError(f"[{section}] must be a table")
        unknown = set(sec) - set(keys)
        if unknown:
            raise ConfigError(f"[{section}] has unknown keys: {', '.join(sorted(unknown))}")
        for key, attr in keys.items():
            if key in sec:
                attr = "deps_paths" if attr == "paths_" else attr
                default = getattr(cfg, attr)
                val = sec[key]
                if isinstance(default, bool) and not isinstance(val, bool):
                    raise ConfigError(f"[{section}].{key} must be true/false")
                if isinstance(default, list) and not isinstance(val, list):
                    raise ConfigError(f"[{section}].{key} must be a list")
                if isinstance(default, float) and isinstance(val, int):
                    val = float(val)
                setattr(cfg, attr, val)
    if cfg.fail_on not in ("critical", "high", "medium", "low", "none"):
        raise ConfigError("general.fail_on must be one of critical/high/medium/low/none")
    return cfg


def load_config(path: Optional[str] = None) -> Config:
    candidates = [path] if path else DEFAULT_CONFIG_PATHS
    for c in candidates:
        p = Path(c).expanduser()
        if p.is_file():
            try:
                data = tomllib.loads(p.read_text(encoding="utf-8"))
            except tomllib.TOMLDecodeError as exc:
                raise ConfigError(f"Config file {p} is not valid TOML: {exc}") from exc
            return from_dict(data, str(p))
        if path:
            raise ConfigError(f"Config file not found: {p}")
    return Config()
