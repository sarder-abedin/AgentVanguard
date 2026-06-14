"""FastAPI sidecar/API service for agent-firewall (requires the `server` extra).

`create_app(config)` builds a `FastAPI` app whose routes all construct a
`PolicyInput` and call the same `Engine.authorize()` used by the SDK and
tool-broker — no policy logic is duplicated here.
"""

from __future__ import annotations

from agent_firewall.server.app import create_app

__all__ = ["create_app"]
