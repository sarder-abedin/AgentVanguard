"""`create_app(config) -> FastAPI` — the sidecar entry point.

The returned app stores one `AgentFirewall` (and therefore one `Engine`) on
`app.state.firewall`, shared by every request handled by this process.
"""

from __future__ import annotations

from fastapi import FastAPI

from agent_firewall.config.schema import Config
from agent_firewall.firewall import AgentFirewall
from agent_firewall.server.routes import router
from agent_firewall.version import __version__


def create_app(config: Config) -> FastAPI:
    app = FastAPI(
        title="agent-firewall",
        description="A workflow-agnostic firewall for LLM-based agentic systems.",
        version=__version__,
    )
    app.state.firewall = AgentFirewall(config)
    app.include_router(router)
    return app
