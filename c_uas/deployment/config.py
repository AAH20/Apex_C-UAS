"""
Deployment configuration for the C-UAS platform.

All configuration comes from environment variables with sensible defaults.
No secrets are hardcoded: API keys are read from the CUAS_API_KEYS
environment variable (comma-separated) or from
~/.c-uas-platform/api_keys.json (a JSON list, or an object with a "keys"
list). The environment variable takes precedence when set.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

_API_KEYS_FILE = Path.home() / ".c-uas-platform" / "api_keys.json"


@dataclass(frozen=True)
class DeploymentConfig:
    """Runtime deployment configuration, every field sourced from env."""

    host: str
    port: int
    api_keys: Tuple[str, ...]
    rate_limit_rps: float
    rate_limit_burst: int
    log_level: str
    structured_logging: bool
    metrics_enabled: bool

    @property
    def auth_required(self) -> bool:
        """Authentication is enforced only when at least one API key is configured."""
        return len(self.api_keys) > 0


def _read_env_list(name: str) -> Tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def load_api_keys() -> Tuple[str, ...]:
    """Load configured API keys.

    CUAS_API_KEYS wins when set. Otherwise read
    ~/.c_uas-platform/api_keys.json if present. Returns an empty tuple when
    nothing is configured, which puts the API in unauthenticated pass-through
    mode (suitable for local development, not production).
    """
    env_keys = _read_env_list("CUAS_API_KEYS")
    if env_keys:
        return env_keys
    if _API_KEYS_FILE.exists():
        try:
            data = json.loads(_API_KEYS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return ()
        if isinstance(data, list):
            return tuple(str(key) for key in data)
        if isinstance(data, dict):
            return tuple(str(key) for key in data.get("keys", []))
    return ()


def _read_env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _read_env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _read_env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def load_config() -> DeploymentConfig:
    """Load deployment configuration from environment variables."""
    return DeploymentConfig(
        host=os.environ.get("CUAS_API_HOST", "127.0.0.1"),
        port=_read_env_int("CUAS_API_PORT", 8000),
        api_keys=load_api_keys(),
        rate_limit_rps=_read_env_float("CUAS_RATE_LIMIT_RPS", 10.0),
        rate_limit_burst=_read_env_int("CUAS_RATE_LIMIT_BURST", 20),
        log_level=os.environ.get("CUAS_LOG_LEVEL", "INFO"),
        structured_logging=_read_env_bool("CUAS_STRUCTURED_LOGGING", True),
        metrics_enabled=_read_env_bool("CUAS_METRICS_ENABLED", True),
    )
