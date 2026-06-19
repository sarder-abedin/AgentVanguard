"""FastAPI dependency that returns the per-app `AgentVanguard` instance
created by `create_app` and stored on `app.state.firewall`."""

from __future__ import annotations

from fastapi import Request

from agentvanguard.firewall import AgentVanguard


def get_firewall(request: Request) -> AgentVanguard:
    """FastAPI dependency: pulls the process-wide `AgentVanguard` instance off
    `request.app.state.firewall` (set once by `server.app.create_app`) so
    every route handler can declare `firewall: AgentVanguard =
    Depends(get_firewall)` instead of importing or constructing one itself.

    Returns the same `AgentVanguard`/`Engine` for every request handled by
    this process -- there is no per-request construction here.
    """

    # `app.state` is typed as `State` (effectively `Any`-valued attributes),
    # so mypy cannot infer the attribute's type; the cast back to
    # `AgentVanguard` is asserted via the ignore comment rather than a
    # runtime check.
    return request.app.state.firewall  # type: ignore[no-any-return]
