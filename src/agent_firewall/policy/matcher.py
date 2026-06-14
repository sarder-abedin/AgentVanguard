"""Evaluate a `rules:` `match` dict (see `config/schema.py:RuleConfig`)
against a `PolicyInput` plus the findings/risk score produced so far.

Supported `match` keys (AND-combined):

- `tool`: exact match against `PolicyInput.tool`.
- `workflow`: exact match against `PolicyInput.workflow` (falling back to
  `PolicyInput.agent.workflow`).
- `agent`: exact match against `PolicyInput.agent.name`.
- `actor.tenant_id`: exact match against `PolicyInput.actor.tenant_id`.
- `actor.roles_any`: true if `PolicyInput.actor.roles` intersects the given list.
- `provenance_in`: true if any provenance label attached to
  `PolicyInput.content` (when it is a list of `ContentItem`) is in the
  given list.
- `finding_types_any`: true if any finding produced so far has a `type` in
  the given list.
- `risk_score_gte`: true if the risk score produced so far is >= the given
  value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_firewall.core.enums import ProvenanceLabel
from agent_firewall.core.errors import PolicyError
from agent_firewall.core.models import ContentItem, Finding, PolicyInput

_KNOWN_KEYS = {
    "tool",
    "workflow",
    "agent",
    "actor.tenant_id",
    "actor.roles_any",
    "provenance_in",
    "finding_types_any",
    "risk_score_gte",
}


@dataclass
class MatchContext:
    """Everything a `rules:` entry can match against, in addition to the
    `PolicyInput` itself."""

    policy_input: PolicyInput
    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0


def _content_provenances(policy_input: PolicyInput) -> set[ProvenanceLabel]:
    if isinstance(policy_input.content, list):
        return {
            item.provenance for item in policy_input.content if isinstance(item, ContentItem)
        }
    return set()


def matches(match: dict[str, Any], ctx: MatchContext) -> bool:
    """Return True if every key in `match` matches `ctx` (empty `match`
    always matches)."""

    for key, expected in match.items():
        if key not in _KNOWN_KEYS:
            raise PolicyError(f"unknown rule match key: {key!r}")

        if key == "tool":
            if ctx.policy_input.tool != expected:
                return False

        elif key == "workflow":
            actual = ctx.policy_input.workflow
            if actual is None and ctx.policy_input.agent is not None:
                actual = ctx.policy_input.agent.workflow
            if actual != expected:
                return False

        elif key == "agent":
            actual = ctx.policy_input.agent.name if ctx.policy_input.agent else None
            if actual != expected:
                return False

        elif key == "actor.tenant_id":
            actual = ctx.policy_input.actor.tenant_id if ctx.policy_input.actor else None
            if actual != expected:
                return False

        elif key == "actor.roles_any":
            roles = set(ctx.policy_input.actor.roles) if ctx.policy_input.actor else set()
            if not roles.intersection(expected):
                return False

        elif key == "provenance_in":
            if not _content_provenances(ctx.policy_input).intersection(expected):
                return False

        elif key == "finding_types_any":
            finding_types = {f.type for f in ctx.findings}
            if not finding_types.intersection(expected):
                return False

        elif key == "risk_score_gte":
            if ctx.risk_score < float(expected):
                return False

    return True
