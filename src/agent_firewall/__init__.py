"""agent-firewall: a workflow-agnostic firewall for LLM-based agentic systems.

See `docs/architecture.md` for the design and `examples/` for quick-starts.
"""

from __future__ import annotations

from agent_firewall.core.enums import ActionType, DecisionAction, RiskTier, SideEffect
from agent_firewall.core.models import Actor, AgentIdentity, Decision, ToolManifest
from agent_firewall.firewall import AgentFirewall
from agent_firewall.version import __version__

__all__ = [
    "AgentFirewall",
    "Actor",
    "AgentIdentity",
    "ToolManifest",
    "ActionType",
    "SideEffect",
    "RiskTier",
    "Decision",
    "DecisionAction",
    "__version__",
]
