"""`create_app(config) -> FastAPI` — the sidecar entry point.

The returned app stores one `AgentVanguard` (and therefore one `Engine`) on
`app.state.firewall`, shared by every request handled by this process.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from agentvanguard.config.schema import Config
from agentvanguard.firewall import AgentVanguard
from agentvanguard.server.routes import router
from agentvanguard.version import __version__

logger = logging.getLogger(__name__)


def create_app(config: Config) -> FastAPI:
    """Build the sidecar `FastAPI` application from a loaded `Config`.

    Constructs exactly one `AgentVanguard` (and therefore one `Engine`) for
    the lifetime of the returned app, stores it on `app.state.firewall` for
    `server.deps.get_firewall` to hand out as a request dependency, and
    mounts all HTTP routes from `server.routes.router`. Called once per
    process by the `agentvanguard serve` CLI command (or by a caller running
    its own `uvicorn`/ASGI server).
    """

    # `title`/`description`/`version` only affect the auto-generated OpenAPI
    # schema and docs UI (`/docs`, `/redoc`) -- they have no effect on
    # request handling.
    app = FastAPI(
        title="agentvanguard",
        description="A workflow-agnostic firewall for LLM-based agentic systems.",
        version=__version__,
    )
    # One Engine per process, shared by every request via the `get_firewall`
    # dependency -- see the architecture invariant in CLAUDE.md.
    app.state.firewall = AgentVanguard(config)
    app.include_router(router)

    # `config.server.api_keys` empty means `require_api_key` (see
    # `server/deps.py`) is a no-op for every route -- every caller that can
    # reach this process over the network is implicitly trusted. That's a
    # reasonable default for local development or a deployment that already
    # terminates auth at a reverse proxy / mTLS boundary in front of this
    # process, but it's silent unless logged here.
    if not config.server.api_keys:
        logger.warning(
            "agentvanguard serve: no config.server.api_keys configured -- "
            "the sidecar HTTP API is unauthenticated. Set server.api_keys "
            "or deploy behind an authenticating reverse proxy / mTLS boundary."
        )

    return app
