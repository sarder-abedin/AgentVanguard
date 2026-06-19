"""agentvanguard: a workflow-agnostic firewall for LLM-based agentic systems.

See `docs/architecture.md` for the design and `examples/` for quick-starts.
"""

# `from __future__ import annotations` makes all annotations in this module
# lazily-evaluated strings (PEP 563), which is required so the `"AgentVanguard"`
# forward references used elsewhere in the codebase resolve without circular
# imports at module load time.
from __future__ import annotations

# Re-export the small set of enums/models/exceptions that most callers need
# to construct a `ToolManifest` or inspect a `Decision`, without requiring
# them to know the internal `agentvanguard.core.*` package layout.
from agentvanguard.core.enums import ActionType, DecisionAction, RiskTier, SideEffect
from agentvanguard.core.models import Actor, AgentIdentity, Decision, ToolManifest

# `AgentVanguard` is the public SDK entry point (see firewall.py); importing
# it here makes `from agentvanguard import AgentVanguard` work.
from agentvanguard.firewall import AgentVanguard
from agentvanguard.version import __version__

# Explicit public API of the top-level `agentvanguard` package. Anything not
# listed here is still importable via its fully-qualified submodule path
# (e.g. `agentvanguard.engine.Engine`) but is not part of the documented,
# stable surface re-exported at package level.
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
