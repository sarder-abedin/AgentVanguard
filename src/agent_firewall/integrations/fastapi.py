"""Re-export of `AgentFirewallMiddleware` for call sites that prefer
`from agent_firewall.integrations.fastapi import AgentFirewallMiddleware`.

`AgentFirewallMiddleware` is pure ASGI and works with FastAPI/Starlette (or
any other ASGI 3 framework) unchanged; this module exists only for
discoverability:

    from fastapi import FastAPI
    from agent_firewall import AgentFirewall
    from agent_firewall.integrations.fastapi import AgentFirewallMiddleware

    app = FastAPI()
    firewall = AgentFirewall.from_config("agent_firewall.yaml")
    app.add_middleware(AgentFirewallMiddleware, firewall=firewall)
"""

from __future__ import annotations

from agent_firewall.integrations.asgi import AgentFirewallMiddleware

__all__ = ["AgentFirewallMiddleware"]
