"""Framework integrations that mediate an existing service's traffic through
`Engine.authorize()` -- see `agentvanguard.integrations.asgi`."""

from __future__ import annotations

# This package intentionally has no re-exports of its own: callers import
# `AgentVanguardMiddleware` directly from `agentvanguard.integrations.asgi`
# (the canonical, framework-agnostic implementation) or from
# `agentvanguard.integrations.fastapi` (a same-class re-export kept for
# discoverability by FastAPI users). Nothing needs to be defined here.
