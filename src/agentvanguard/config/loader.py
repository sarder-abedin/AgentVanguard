"""Resolve and load `agentvanguard.yaml`.

Resolution order: explicit `path` argument > `$AGENTVANGUARD_CONFIG` env var
> `./agentvanguard.yaml` > built-in defaults (`config/defaults.py`).
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import ValidationError

from agentvanguard.config.defaults import get_default_config
from agentvanguard.config.schema import Config
from agentvanguard.core.errors import ConfigError

CONFIG_ENV_VAR = "AGENTVANGUARD_CONFIG"
DEFAULT_CONFIG_FILENAME = "agentvanguard.yaml"


def resolve_config_path(path: str | None = None) -> Path | None:
    """Return the config file path to load, or `None` if none was found and
    the in-memory defaults should be used."""

    if path:
        return Path(path)

    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        return Path(env_path)

    default_path = Path(DEFAULT_CONFIG_FILENAME)
    if default_path.exists():
        return default_path

    return None


def load(path: str | None = None) -> Config:
    """Load and validate `Config` from `path` (or the resolved default
    location). Falls back to `get_default_config()` if no file is found.

    Raises `ConfigError` if a file is found but is missing, malformed, or
    fails cross-reference validation.
    """

    resolved = resolve_config_path(path)
    if resolved is None:
        return get_default_config()

    if not resolved.exists():
        raise ConfigError(f"config file not found: {resolved}")

    try:
        raw = yaml.safe_load(resolved.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {resolved}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{resolved}: top-level YAML must be a mapping")

    try:
        config = Config.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid config in {resolved}:\n{exc}") from exc

    errors = config.validate_references()
    if errors:
        raise ConfigError(
            f"config validation failed for {resolved}:\n" + "\n".join(f"  - {e}" for e in errors)
        )

    return config
