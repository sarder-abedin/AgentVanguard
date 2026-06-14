"""FastAPI dependency that returns the per-app `AgentFirewall` instance
created by `create_app` and stored on `app.state.firewall`."""

from __future__ import annotations

from fastapi import Request

from agent_firewall.firewall import AgentFirewall


def get_firewall(request: Request) -> AgentFirewall:
    return request.app.state.firewall  # type: ignore[no-any-return]
