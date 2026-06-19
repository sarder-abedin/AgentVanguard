"""Re-export of `AgentVanguardMiddleware` for call sites that prefer
`from agentvanguard.integrations.fastapi import AgentVanguardMiddleware`.

`AgentVanguardMiddleware` is pure ASGI and works with FastAPI/Starlette (or
any other ASGI 3 framework) unchanged; this module exists only for
discoverability:

    from fastapi import FastAPI
    from agentvanguard import AgentVanguard
    from agentvanguard.integrations.fastapi import AgentVanguardMiddleware

    app = FastAPI()
    firewall = AgentVanguard.from_config("agentvanguard.yaml")
    app.add_middleware(AgentVanguardMiddleware, firewall=firewall)
"""

from __future__ import annotations

# Plain re-export -- no FastAPI-specific subclassing or wrapping happens
# here; the imported class is pure ASGI and is FastAPI-compatible as-is.
from agentvanguard.integrations.asgi import AgentVanguardMiddleware

# Defines the public surface of this module: only `AgentVanguardMiddleware`
# is meant to be imported from `agentvanguard.integrations.fastapi`.
__all__ = ["AgentVanguardMiddleware"]
