"""Resolve and load `agentvanguard.yaml`.

Resolution order: explicit `path` argument > `$AGENTVANGUARD_CONFIG` env var
> `./agentvanguard.yaml` > built-in defaults (`config/defaults.py`).

This precedence lets every caller -- the CLI's `--config` flag,
`AgentVanguard.from_config()`, the sidecar server, tests -- share one
resolution policy instead of each reimplementing "where's the config file."
The order is deliberately most-specific-wins: an explicit path passed by
the calling code always overrides the environment, which always overrides
a conventionally-named file in the current directory, which always
overrides falling back to safe, fail-closed built-in defaults so the
engine can still start with *no* config at all (e.g. for a quick SDK trial
or a unit test) rather than refusing to run.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import ValidationError

from agentvanguard.config.defaults import get_default_config
from agentvanguard.config.schema import Config
from agentvanguard.core.errors import ConfigError

# Environment variable checked by `resolve_config_path()` when no explicit
# `path` argument is given -- lets deployments (e.g. containers) point at a
# config file without changing code or CLI invocations.
CONFIG_ENV_VAR = "AGENTVANGUARD_CONFIG"
# Conventional filename checked in the current working directory as the
# last concrete lookup before giving up and using in-memory defaults. This
# is also the default `--output` path for `agentvanguard init`/`quickstart`.
DEFAULT_CONFIG_FILENAME = "agentvanguard.yaml"


def resolve_config_path(path: str | None = None) -> Path | None:
    """Return the config file path to load, or `None` if none was found and
    the in-memory defaults should be used."""

    # 1. Explicit argument wins unconditionally -- this is what the CLI's
    #    `--config`/`-c` flag and `AgentVanguard.from_config(path)` pass
    #    through. No existence check here; if the path is wrong, `load()`
    #    below will raise a clear `ConfigError` rather than silently
    #    falling through to a different config.
    if path:
        return Path(path)

    # 2. Environment variable next -- lets ops/deployment tooling pin a
    #    config path without touching invocation code (e.g. set once in a
    #    container's env and every `agentvanguard`/SDK call picks it up).
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        return Path(env_path)

    # 3. Conventional filename in the current directory -- but only if it
    #    actually exists; unlike the previous two cases, there's no
    #    explicit signal from the caller here, so we probe for the file
    #    rather than assuming it should exist.
    default_path = Path(DEFAULT_CONFIG_FILENAME)
    if default_path.exists():
        return default_path

    # 4. Nothing found at any level -- signal the caller (`load()`) to fall
    #    back to the built-in, dependency-free default `Config`.
    return None


def load(path: str | None = None) -> Config:
    """Load and validate `Config` from `path` (or the resolved default
    location). Falls back to `get_default_config()` if no file is found.

    Raises `ConfigError` if a file is found but is missing, malformed, or
    fails cross-reference validation.
    """

    resolved = resolve_config_path(path)
    if resolved is None:
        # No path argument, no env var, and no conventional file present --
        # this is the "just works with zero setup" path, returning the
        # same safe, fail-closed `Config()` defaults documented in
        # `config/schema.py` and `config/defaults.py`.
        return get_default_config()

    if not resolved.exists():
        # A path *was* resolved (explicit argument or env var) but the file
        # doesn't exist -- this is always an error, never a silent
        # fallback, since the caller clearly expected a specific file.
        raise ConfigError(f"config file not found: {resolved}")

    # Parse the YAML; `yaml.safe_load` (not `yaml.load`) avoids executing
    # arbitrary Python tags embedded in the file. `or {}` turns an empty
    # file (which parses to `None`) into an empty mapping so the type check
    # below and `Config.model_validate` both see a dict.
    try:
        raw = yaml.safe_load(resolved.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {resolved}: {exc}") from exc

    if not isinstance(raw, dict):
        # Guards against a syntactically valid YAML document that isn't a
        # mapping at the top level (e.g. a bare list or scalar) -- pydantic
        # would otherwise raise a less helpful error.
        raise ConfigError(f"{resolved}: top-level YAML must be a mapping")

    # Validate the raw dict against the `Config` pydantic schema -- this
    # checks types, enum membership, and defaults for every field declared
    # in `schema.py`, but *not* cross-section references (that's next).
    try:
        config = Config.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid config in {resolved}:\n{exc}") from exc

    # Cross-reference validation: checks that fields in one section
    # actually refer to things declared in another section (e.g. a
    # workflow's `allowed_tools` must name tools that exist under
    # `tools:`). This can't be expressed as a single-field pydantic
    # validator since it spans multiple top-level sections, so it's a
    # separate explicit step after the schema itself validates cleanly.
    errors = config.validate_references()
    if errors:
        raise ConfigError(
            f"config validation failed for {resolved}:\n" + "\n".join(f"  - {e}" for e in errors)
        )

    return config
