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

from agentvanguard.integrations.asgi import AgentVanguardMiddleware

__all__ = ["AgentVanguardMiddleware"]
