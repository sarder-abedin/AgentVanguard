"""Exceptions shared across the engine, config loader, and integrations."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_firewall.core.models import Decision


class AgentFirewallError(Exception):
    """Base class for all agent-firewall errors."""


class ConfigError(AgentFirewallError):
    """Raised when `agent_firewall.yaml` is missing, invalid, or internally
    inconsistent (e.g. a workflow references an unknown tool)."""


class PolicyError(AgentFirewallError):
    """Raised when the policy evaluator encounters a malformed rule or an
    unresolvable reference (e.g. an unknown detector name)."""


class FirewallBlockedError(AgentFirewallError):
    """Raised by `wrap_tool`/`wrap_agent` when `Engine.authorize()` returns a
    `DENY` decision (or a `REQUIRE_USER_CONFIRMATION` that the configured
    `ApprovalProvider` rejects)."""

    def __init__(self, decision: "Decision") -> None:
        self.decision = decision
        reasons = "; ".join(decision.reasons) or "no reason given"
        super().__init__(f"blocked by agent-firewall: {decision.decision.value} ({reasons})")
