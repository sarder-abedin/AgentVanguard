"""`PolicyBundleSource` protocol -- pluggable sources of `Config` bundles for
a hybrid local/cloud control plane.

`LocalFileSource` wraps `config.loader.load` (the Phase 1/2 default, and
still the implicit source whenever an `Engine` is built via
`AgentFirewall.from_config`). `HttpPolicyBundleSource` fetches a bundle from
a central policy server -- `fail_mode` governs what happens if that fetch
fails:

- `"closed"` (default, fail-closed): raise `ConfigError`.
- `"open"`: fall back to the last successfully fetched bundle, or the
  built-in defaults if none has ever been fetched.

Neither source is wired into `config.loader.load()` automatically --
constructing an `Engine`/`AgentFirewall` from a fetched `Config` is the
caller's responsibility (e.g. poll `HttpPolicyBundleSource.fetch()` on a
schedule and rebuild the `AgentFirewall`).
"""

from __future__ import annotations

import json
import urllib.request
from typing import Literal, Protocol, runtime_checkable

import yaml
from pydantic import ValidationError

from agent_firewall.config.defaults import get_default_config
from agent_firewall.config.loader import load
from agent_firewall.config.schema import Config
from agent_firewall.core.errors import ConfigError

FailMode = Literal["open", "closed"]


@runtime_checkable
class PolicyBundleSource(Protocol):
    def fetch(self) -> Config:
        """Return the current `Config`. Behavior on failure depends on the
        implementation (and, for remote sources, its `fail_mode`)."""
        ...


class LocalFileSource:
    """Wraps `config.loader.load(path)` -- the Phase 1/2 default."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path

    def fetch(self) -> Config:
        return load(self.path)


class HttpPolicyBundleSource:
    """Fetches an `agent_firewall.yaml`-shaped bundle (YAML or JSON, based on
    the response `Content-Type`) from `url` via HTTP GET."""

    def __init__(self, url: str, *, fail_mode: FailMode = "closed", timeout: float = 10.0) -> None:
        self.url = url
        self.fail_mode = fail_mode
        self.timeout = timeout
        self._cached: Config | None = None

    def fetch(self) -> Config:
        try:
            config = self._fetch_and_validate()
        except (OSError, ConfigError) as exc:
            if self.fail_mode == "open":
                return self._cached if self._cached is not None else get_default_config()
            raise ConfigError(f"failed to fetch policy bundle from {self.url}: {exc}") from exc

        self._cached = config
        return config

    def _fetch_and_validate(self) -> Config:
        request = urllib.request.Request(self.url, headers={"Accept": "application/json, application/yaml"})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
            raw_bytes = response.read()
            content_type = response.headers.get("Content-Type", "")

        if "json" in content_type:
            raw = json.loads(raw_bytes)
        else:
            raw = yaml.safe_load(raw_bytes)

        if not isinstance(raw, dict):
            raise ConfigError(f"policy bundle from {self.url} must be a mapping")

        try:
            config = Config.model_validate(raw)
        except ValidationError as exc:
            raise ConfigError(f"invalid policy bundle from {self.url}:\n{exc}") from exc

        errors = config.validate_references()
        if errors:
            raise ConfigError(
                f"policy bundle validation failed for {self.url}:\n" + "\n".join(f"  - {e}" for e in errors)
            )

        return config
