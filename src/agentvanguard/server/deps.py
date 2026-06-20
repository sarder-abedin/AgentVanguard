"""FastAPI dependencies shared by `server/routes.py`: `get_firewall` (the
per-app `AgentVanguard` instance) and `require_api_key` (sidecar
authentication)."""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, Request

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


def require_api_key(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """FastAPI dependency enforcing `config.server.api_keys`, applied to
    every policy-evaluating/observability route in `server/routes.py`
    (deliberately *not* `/healthz`/`/readyz`, which orchestrator liveness/
    readiness probes typically cannot attach a secret header to).

    Accepts the key via either `Authorization: Bearer <token>` or
    `X-API-Key: <token>`, compared with `hmac.compare_digest` (constant-time,
    so response timing can't be used to brute-force a valid key one
    character at a time). If `config.server.api_keys` is empty (the
    documented default), authentication is a no-op -- the operator is
    expected to put an authenticating reverse proxy / mTLS boundary in front
    of the sidecar instead; `server.app.create_app` logs a startup warning
    in that case so the gap is visible rather than silent.
    """

    firewall: AgentVanguard = request.app.state.firewall
    api_keys = firewall.engine.config.server.api_keys
    if not api_keys:
        return

    presented = x_api_key
    if presented is None and authorization is not None:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            presented = token

    if presented is None or not any(hmac.compare_digest(presented, key) for key in api_keys):
        raise HTTPException(status_code=401, detail="missing or invalid API key")
