"""FastAPI sidecar/API service for agentvanguard (requires the `server` extra).

`create_app(config)` builds a `FastAPI` app whose routes all construct a
`PolicyInput` and call the same `Engine.authorize()` used by the SDK and
tool-broker — no policy logic is duplicated here.
"""

from __future__ import annotations

# Re-exported so callers can do `from agentvanguard.server import create_app`
# instead of reaching into the `app` submodule directly.
from agentvanguard.server.app import create_app

# Defines the public surface of this package: only `create_app` is meant to
# be imported from `agentvanguard.server` by external callers (e.g. the
# `agentvanguard serve` CLI command, or a `uvicorn` entry point).
__all__ = ["create_app"]
