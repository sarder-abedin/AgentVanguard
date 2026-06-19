"""`PolicyBundleSource` protocol -- pluggable sources of `Config` bundles for
a hybrid local/cloud control plane.

`LocalFileSource` wraps `config.loader.load` (the Phase 1/2 default, and
still the implicit source whenever an `Engine` is built via
`AgentVanguard.from_config`). `HttpPolicyBundleSource` fetches a bundle from
a central policy server -- `fail_mode` governs what happens if that fetch
fails:

- `"closed"` (default, fail-closed): raise `ConfigError`.
- `"open"`: fall back to the last successfully fetched bundle, or the
  built-in defaults if none has ever been fetched.

Neither source is wired into `config.loader.load()` automatically --
constructing an `Engine`/`AgentVanguard` from a fetched `Config` is the
caller's responsibility (e.g. poll `HttpPolicyBundleSource.fetch()` on a
schedule and rebuild the `AgentVanguard`).
"""

from __future__ import annotations

import json
import urllib.request
from typing import Literal, Protocol, runtime_checkable

import yaml
from pydantic import ValidationError

from agentvanguard.config.defaults import get_default_config
from agentvanguard.config.loader import load
from agentvanguard.config.schema import Config
from agentvanguard.core.errors import ConfigError

# The two legal values for `HttpPolicyBundleSource.fail_mode`; see the
# module docstring above for what each one does on a fetch failure.
FailMode = Literal["open", "closed"]


@runtime_checkable
class PolicyBundleSource(Protocol):
    """Common interface for anything that can produce a `Config` bundle --
    whether read from a local file (`LocalFileSource`) or fetched from a
    remote policy server (`HttpPolicyBundleSource`). `@runtime_checkable`
    lets callers `isinstance()`-check against this `Protocol` without
    requiring sources to explicitly subclass it.
    """

    def fetch(self) -> Config:
        """Return the current `Config`. Behavior on failure depends on the
        implementation (and, for remote sources, its `fail_mode`)."""
        ...


class LocalFileSource:
    """Wraps `config.loader.load(path)` -- the Phase 1/2 default.

    Exists so call sites that want to be agnostic between local and remote
    config sources can hold a `PolicyBundleSource` and call `fetch()`
    uniformly, even when the underlying source is just a local YAML file
    re-read from disk on every call (`load` does its own parsing/validation
    each time; this class adds no caching of its own).
    """

    def __init__(self, path: str | None = None) -> None:
        # `path` is forwarded as-is to `config.loader.load`; `None` defers
        # to that function's own default path-resolution behavior.
        self.path = path

    def fetch(self) -> Config:
        return load(self.path)


class HttpPolicyBundleSource:
    """Fetches an `agentvanguard.yaml`-shaped bundle (YAML or JSON, based on
    the response `Content-Type`) from `url` via HTTP GET.

    This is the remote half of the hybrid control plane: a central policy
    server can serve the same shape of config that `LocalFileSource` reads
    from disk, letting a fleet of agentvanguard deployments be centrally
    managed. See the module docstring for the full `fail_mode` semantics;
    in short, `"closed"` makes a fetch failure raise so the caller's retry
    loop / health check notices and the previous in-process `Config` keeps
    being used, while `"open"` makes a fetch failure transparently return
    the last good bundle (or built-in defaults if none was ever fetched)
    so a transient outage of the policy server can't take the bundle itself
    offline.
    """

    def __init__(self, url: str, *, fail_mode: FailMode = "closed", timeout: float = 10.0) -> None:
        # URL of the central policy server endpoint serving the bundle.
        self.url = url
        # Governs what `fetch()` does when the HTTP call or bundle
        # validation fails -- see class/module docstrings.
        self.fail_mode = fail_mode
        # Per-request timeout, in seconds, for the underlying HTTP GET.
        self.timeout = timeout
        # The most recently *successfully* fetched+validated `Config`, kept
        # only so `fail_mode="open"` has something to fall back to. Never
        # set from a failed fetch -- only updated at the end of `fetch()`
        # once `_fetch_and_validate()` has returned without raising.
        self._cached: Config | None = None

    def fetch(self) -> Config:
        """Fetch, parse, and validate the bundle at `self.url`.

        On success, caches and returns the new `Config`. On failure
        (network/HTTP error as `OSError`, or a parse/schema/reference
        validation failure as `ConfigError` from `_fetch_and_validate`):

        - `fail_mode == "open"`: swallow the error and return the last
          successfully cached `Config`, or `get_default_config()` if
          nothing has ever been fetched successfully -- the caller always
          gets *some* valid `Config` back, never an exception.
        - otherwise (`"closed"`, the default): re-raise as a `ConfigError`
          describing the failure, so the caller (which is responsible for
          deciding what to do with a stale or absent bundle) is forced to
          handle it explicitly rather than silently running with stale or
          default policy.
        """

        try:
            config = self._fetch_and_validate()
        except (OSError, ConfigError) as exc:
            if self.fail_mode == "open":
                return self._cached if self._cached is not None else get_default_config()
            raise ConfigError(f"failed to fetch policy bundle from {self.url}: {exc}") from exc

        self._cached = config
        return config

    def _fetch_and_validate(self) -> Config:
        """Perform the actual HTTP GET, decode the body, and fully validate
        it as a `Config` -- the part of `fetch()` that can fail and is
        retried/cached around above.

        Decoding is content-negotiated: the response `Content-Type` decides
        whether the body is parsed as JSON or YAML (YAML is the fallback,
        since `agentvanguard.yaml` bundles are normally YAML). The decoded
        mapping is then run through the same two-stage validation any
        config from `config.loader.load` goes through: pydantic schema
        validation (`Config.model_validate`) followed by cross-field
        reference validation (`config.validate_references()`, e.g. policy
        rules referencing tool names that must actually be declared) --
        ensuring a bundle fetched from a remote, less-trusted source is held
        to exactly the same correctness bar as a local file.
        """

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

        # Beyond per-field schema validation, check cross-references within
        # the config (e.g. rules that name tools/workflows that must exist
        # elsewhere in the same bundle) -- a bundle can be schema-valid yet
        # internally inconsistent, and this catches that before it's ever
        # handed to an `Engine`.
        errors = config.validate_references()
        if errors:
            raise ConfigError(
                f"policy bundle validation failed for {self.url}:\n" + "\n".join(f"  - {e}" for e in errors)
            )

        return config
