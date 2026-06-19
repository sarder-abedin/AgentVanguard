"""Re-exports for declaring `ToolManifest`s without reaching into `core`."""

from __future__ import annotations

# `ToolManifest` is the pydantic model integrators instantiate to register a
# tool (e.g. `ToolManifest(name="send_email", action_type=ActionType.SEND_EXTERNAL, ...)`).
# `ActionType`/`SideEffect`/`RiskTier` are the enums its fields are typed
# with, re-exported here so a manifest can be built with a single import
# (`from agentvanguard.tools import ToolManifest, ActionType, ...`) instead of
# reaching into `agentvanguard.core.enums` / `agentvanguard.core.models`.
from agentvanguard.core.enums import ActionType, RiskTier, SideEffect
from agentvanguard.core.models import ToolManifest

# Public surface of this module: only these four names are intended to be
# imported from `agentvanguard.tools`.
__all__ = ["ToolManifest", "ActionType", "SideEffect", "RiskTier"]
