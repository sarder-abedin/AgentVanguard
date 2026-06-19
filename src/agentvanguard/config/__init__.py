"""Configuration schema, defaults, and loader for `agentvanguard.yaml`.

This package has three modules, each with a distinct job:
- `schema.py` defines the pydantic models (`Config` and its sub-sections)
  that `agentvanguard.yaml` is validated against.
- `defaults.py` provides `get_default_config()` (the in-memory fallback
  `Config` used when no file is found) and `DEFAULT_CONFIG_YAML` (the
  annotated template `agentvanguard init` writes to disk).
- `loader.py` resolves which config file (if any) to read, parses it, and
  validates it against `schema.py`, raising `ConfigError` on any failure.
"""
