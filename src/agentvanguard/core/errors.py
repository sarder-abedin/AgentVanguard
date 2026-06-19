"""Exceptions shared across the engine, config loader, and integrations."""

from __future__ import annotations

from typing import TYPE_CHECKING

# `Decision` is only needed for the type annotation on `VanguardBlockedError`.
# Importing it under `TYPE_CHECKING` avoids a real runtime import — `errors.py`
# is imported very early (by `core/models.py` indirectly and by most other
# packages), so keeping this import type-checking-only avoids any risk of a
# circular-import cycle with `agentvanguard.core.models`.
if TYPE_CHECKING:
    from agentvanguard.core.models import Decision


class AgentVanguardError(Exception):
    """Base class for all agentvanguard errors.

    Every exception this package raises deliberately on purpose (as opposed
    to incidental/library exceptions like `ValueError`) subclasses this, so
    callers can write a single `except AgentVanguardError:` to catch any
    agentvanguard-specific failure mode (config problems, policy problems, or
    an enforced block) without having to enumerate each subclass.
    """


class ConfigError(AgentVanguardError):
    """Raised when `agentvanguard.yaml` is missing, invalid, or internally
    inconsistent (e.g. a workflow references an unknown tool).

    Typically raised during `config.loader.load()` / startup (CLI commands
    like `validate-config`/`doctor`, or `AgentVanguard.from_config`) — i.e.
    before any request is ever evaluated — so it surfaces a broken deployment
    immediately rather than failing individual requests later. Also raised by
    `firewall.wrap_tool` when a tool name string is passed but no matching
    `ToolManifest` has been registered.
    """


class PolicyError(AgentVanguardError):
    """Raised when the policy evaluator encounters a malformed rule or an
    unresolvable reference (e.g. an unknown detector name).

    Raised from `policy.evaluator.PolicyEvaluator.evaluate()` while applying
    match-dict rules from config; indicates the loaded policy/rule set itself
    is broken, as distinct from `ConfigError` (broader config-file problems)
    or a normal `DENY` decision (the policy is well-formed but the request is
    disallowed).
    """


class VanguardBlockedError(AgentVanguardError):
    """Raised by `wrap_tool`/`wrap_agent` when `Engine.authorize()` returns a
    `DENY` decision (or a `REQUIRE_USER_CONFIRMATION` that the configured
    `ApprovalProvider` rejects).

    This is the exception integrators should expect (and typically catch) at
    the call site of a firewall-wrapped tool or agent: it signals that the
    action was actively stopped by policy, not that something went wrong
    internally. The offending `Decision` (with its `reasons`, `risk_score`,
    and `trace_id`) is attached as `self.decision` so callers can inspect
    *why* the call was blocked and correlate it with the audit log.
    """

    def __init__(self, decision: "Decision") -> None:
        # Keep the full Decision object available to callers (e.g. to log
        # `decision.trace_id` or inspect `decision.reasons` programmatically)
        # rather than only exposing the stringified message.
        self.decision = decision
        reasons = "; ".join(decision.reasons) or "no reason given"
        super().__init__(f"blocked by agentvanguard: {decision.decision.value} ({reasons})")
