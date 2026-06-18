"""`create_app(config) -> FastAPI` — the sidecar entry point.

The returned app stores one `AgentVanguard` (and therefore one `Engine`) on
`app.state.firewall`, shared by every request handled by this process.
"""

from __future__ import annotations

from fastapi import FastAPI

from agentvanguard.config.schema import Config
from agentvanguard.firewall import AgentVanguard
from agentvanguard.server.routes import router
from agentvanguard.version import __version__


def create_app(config: Config) -> FastAPI:
    app = FastAPI(
        title="agentvanguard",
        description="A workflow-agnostic firewall for LLM-based agentic systems.",
        version=__version__,
    )
    app.state.firewall = AgentVanguard(config)
    app.include_router(router)
    return app
