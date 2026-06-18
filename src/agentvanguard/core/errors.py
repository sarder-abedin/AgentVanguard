"""Exceptions shared across the engine, config loader, and integrations."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentvanguard.core.models import Decision


class AgentVanguardError(Exception):
    """Base class for all agentvanguard errors."""


class ConfigError(AgentVanguardError):
    """Raised when `agentvanguard.yaml` is missing, invalid, or internally
    inconsistent (e.g. a workflow references an unknown tool)."""


class PolicyError(AgentVanguardError):
    """Raised when the policy evaluator encounters a malformed rule or an
    unresolvable reference (e.g. an unknown detector name)."""


class VanguardBlockedError(AgentVanguardError):
    """Raised by `wrap_tool`/`wrap_agent` when `Engine.authorize()` returns a
    `DENY` decision (or a `REQUIRE_USER_CONFIRMATION` that the configured
    `ApprovalProvider` rejects)."""

    def __init__(self, decision: "Decision") -> None:
        self.decision = decision
        reasons = "; ".join(decision.reasons) or "no reason given"
        super().__init__(f"blocked by agentvanguard: {decision.decision.value} ({reasons})")
