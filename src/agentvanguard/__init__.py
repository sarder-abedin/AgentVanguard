"""agentvanguard: a workflow-agnostic firewall for LLM-based agentic systems.

See `docs/architecture.md` for the design and `examples/` for quick-starts.
"""

from __future__ import annotations

from agentvanguard.core.enums import ActionType, DecisionAction, RiskTier, SideEffect
from agentvanguard.core.models import Actor, AgentIdentity, Decision, ToolManifest
from agentvanguard.firewall import AgentVanguard
from agentvanguard.version import __version__

__all__ = [
    "AgentVanguard",
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
