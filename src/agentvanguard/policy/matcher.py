"""Evaluate a `rules:` `match` dict (see `config/schema.py:RuleConfig`)
against a `PolicyInput` plus the findings/risk score produced so far.

A `match` dict is a small AND-combined predicate: every key present in the
dict must match for the overall rule to fire (an empty `match` dict matches
everything). This module is the only place that interprets those keys, so
the meaning of each key lives here rather than in `config/schema.py`.

Supported `match` keys (AND-combined):

- `tool`: exact string match against `PolicyInput.tool` (the tool name being
  called, e.g. `"send_email"`). Only meaningful for `action == tool_call`
  inputs; `PolicyInput.tool` is `None` otherwise, so the rule simply won't
  match.
- `workflow`: exact string match against `PolicyInput.workflow` (falling
  back to `PolicyInput.agent.workflow` if `PolicyInput.workflow` itself is
  unset) — i.e. which named workflow (from `config.workflows`) this request
  belongs to.
- `agent`: exact string match against `PolicyInput.agent.name` — which
  agent identity issued the request.
- `actor.tenant_id`: exact string match against `PolicyInput.actor.tenant_id`
  — which tenant/customer the human or service actor behind the request
  belongs to, for multi-tenant deployments.
- `actor.roles_any`: true if `PolicyInput.actor.roles` (the set of roles
  granted to the actor) intersects the given list — i.e. "matches if the
  actor has *any* of these roles".
- `provenance_in`: true if any provenance label attached to
  `PolicyInput.content` (when it is a list of `ContentItem`) is in the
  given list — i.e. "matches if any chunk of content came from one of
  these sources" (e.g. `retrieved_doc`, `tool_output`).
- `finding_types_any`: true if any finding produced so far (by the guard
  stage(s) that ran before custom rules are evaluated, see
  `evaluator.py:_evaluate_rules`) has a `type` in the given list — i.e.
  "matches if any of these specific detector findings already fired".
- `risk_score_gte`: true if the risk score produced so far (the max across
  all `Verdict`s produced before rule evaluation) is >= the given value —
  a numeric threshold gate.

Example `match` dict, combining several keys (all must hold for the rule to
match):

    match:
      workflow: "finance_invoice_review"
      actor.roles_any: ["finance_analyst", "finance_admin"]
      risk_score_gte: 0.5

This matches requests in the `finance_invoice_review` workflow, made by an
actor with the `finance_analyst` or `finance_admin` role, where the risk
score accumulated by the guards so far is at least 0.5. A request in a
different workflow, or made by someone without either role, or with a risk
score of 0.4, would not match — every present key must be satisfied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentvanguard.core.enums import ProvenanceLabel
from agentvanguard.core.errors import PolicyError
from agentvanguard.core.models import ContentItem, Finding, PolicyInput

# The exhaustive set of `match` dict keys this module knows how to
# interpret. `matches()` raises `PolicyError` for any key not in this set,
# so a typo'd or not-yet-implemented key in config fails loudly (fail-closed)
# at evaluation time rather than silently being ignored.
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
    """Collect the distinct `ProvenanceLabel`s attached to `policy_input.content`.

    `PolicyInput.content` can either be a plain string (no provenance
    metadata available) or a `list[ContentItem]` where each item carries its
    own `provenance` label (e.g. a prompt assembled from a user message plus
    several retrieved-document chunks). This returns the empty set whenever
    `content` is not a list of `ContentItem`, so `provenance_in` simply never
    matches for plain-string content.
    """

    if isinstance(policy_input.content, list):
        return {
            item.provenance for item in policy_input.content if isinstance(item, ContentItem)
        }
    return set()


def matches(match: dict[str, Any], ctx: MatchContext) -> bool:
    """Return True if every key in `match` matches `ctx` (empty `match`
    always matches)."""

    # AND-combine every key in `match`: as soon as any single key fails to
    # match, short-circuit and return False for the whole rule. If the loop
    # runs to completion without any key failing (including the trivial case
    # where `match` is empty and the loop body never runs), the rule matches.
    for key, expected in match.items():
        if key not in _KNOWN_KEYS:
            raise PolicyError(f"unknown rule match key: {key!r}")

        if key == "tool":
            # Exact match against the tool name being called.
            if ctx.policy_input.tool != expected:
                return False

        elif key == "workflow":
            # Exact match against the workflow name, falling back to the
            # calling agent's configured workflow if the policy input itself
            # doesn't carry an explicit `workflow`.
            actual = ctx.policy_input.workflow
            if actual is None and ctx.policy_input.agent is not None:
                actual = ctx.policy_input.agent.workflow
            if actual != expected:
                return False

        elif key == "agent":
            # Exact match against the calling agent's name.
            actual = ctx.policy_input.agent.name if ctx.policy_input.agent else None
            if actual != expected:
                return False

        elif key == "actor.tenant_id":
            # Exact match against the human/service actor's tenant id.
            actual = ctx.policy_input.actor.tenant_id if ctx.policy_input.actor else None
            if actual != expected:
                return False

        elif key == "actor.roles_any":
            # "Any of" match: true if the actor's role set and the expected
            # role list share at least one element. An actor with no roles
            # (or no actor at all) never matches a non-empty `expected` list.
            roles = set(ctx.policy_input.actor.roles) if ctx.policy_input.actor else set()
            if not roles.intersection(expected):
                return False

        elif key == "provenance_in":
            # True if at least one provenance label present on the content
            # (see `_content_provenances` above) is in the expected list.
            if not _content_provenances(ctx.policy_input).intersection(expected):
                return False

        elif key == "finding_types_any":
            # True if at least one finding produced by the guard stage(s)
            # that already ran (passed in via `ctx.findings`) has a `type`
            # in the expected list — lets a rule react to specific detector
            # hits (e.g. escalate further whenever an `SSRF` finding fired).
            finding_types = {f.type for f in ctx.findings}
            if not finding_types.intersection(expected):
                return False

        elif key == "risk_score_gte":
            # Numeric threshold: true if the risk score accumulated by the
            # guard stage(s) so far is at least `expected`.
            if ctx.risk_score < float(expected):
                return False

    return True
