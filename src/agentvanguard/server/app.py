"""`create_app(config) -> FastAPI` — the sidecar entry point.

The returned app stores one `AgentVanguard` (and therefore one `Engine`) on
`app.state.firewall`, shared by every request handled by this process.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agentvanguard.config.schema import Config
from agentvanguard.firewall import AgentVanguard
from agentvanguard.server.limits import BodySizeLimitMiddleware
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
    # No `CORSMiddleware` is added here, deliberately: this sidecar is meant
    # to be called server-to-server (by the agent process/orchestrator
    # running alongside it), not directly from a browser, and a permissive
    # CORS policy would let any third-party web page that can reach this
    # process's network location read `Decision`/`Verdict` responses
    # (including policy reasoning and, on `/v1/check-output`,
    # `redacted_content`) on a victim's behalf via their browser. If a
    # deployment genuinely needs browser-originated requests, add
    # `starlette.middleware.cors.CORSMiddleware` explicitly with an
    # `allow_origins` allow-list scoped to that deployment's own
    # frontend(s) -- never `allow_origins=["*"]` alongside
    # `allow_credentials=True`/an API key, since that combination defeats
    # the same-origin protections CORS exists to provide.
    app = FastAPI(
        title="agentvanguard",
        description="A workflow-agnostic firewall for LLM-based agentic systems.",
        version=__version__,
    )
    # One Engine per process, shared by every request via the `get_firewall`
    # dependency -- see the architecture invariant in CLAUDE.md.
    app.state.firewall = AgentVanguard(config)
    app.include_router(router)
    # Bounds the memory/CPU cost of a single oversized request before it
    # ever reaches routing/pydantic validation -- see
    # `server/limits.py:BodySizeLimitMiddleware`.
    app.add_middleware(BodySizeLimitMiddleware, max_body_bytes=config.server.max_request_body_bytes)
    # Without this, an unhandled exception falls through to Starlette's
    # default `ServerErrorMiddleware`, which (since `debug=False` here) does
    # not leak a traceback to the client, but also doesn't log one
    # server-side and replies with a bare plain-text body instead of the
    # JSON every other route returns. This handler makes both sides
    # explicit: the full exception (with traceback) is always logged for
    # operators, while the client only ever sees a generic, JSON, detail-free
    # 500 -- never an exception message, file path, or stack trace that
    # could hand an attacker internal implementation details.
    app.add_exception_handler(Exception, _unhandled_exception_handler)

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


async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for any exception not already turned into an HTTP response
    by a route or by FastAPI/pydantic's own validation handling.

    Logs the full exception server-side (so it's actually actionable for an
    operator) and responds with a generic, JSON, no-detail 500 -- the
    exception's message, type, and traceback are deliberately never included
    in the response body, since they can contain internal details (file
    paths, config values, library internals) that shouldn't be exposed to an
    HTTP caller.
    """

    logger.exception("agentvanguard serve: unhandled exception handling %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "internal server error"})
