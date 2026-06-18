"""FastAPI dependency that returns the per-app `AgentVanguard` instance
created by `create_app` and stored on `app.state.firewall`."""

from __future__ import annotations

from fastapi import Request

from agentvanguard.firewall import AgentVanguard


def get_firewall(request: Request) -> AgentVanguard:
    return request.app.state.firewall  # type: ignore[no-any-return]
