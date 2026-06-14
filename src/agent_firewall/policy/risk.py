"""Deterministic risk scoring and `Verdict` -> `Decision` aggregation.

These are the only two numeric/aggregation rules in the engine — every guard
scores its findings with `finding_score`, and `Engine.authorize()` reduces
the resulting `Verdict[]` to one `Decision` with `aggregate`.
"""

from __future__ import annotations

from collections.abc import Iterable

from agent_firewall.core.enums import DecisionAction, ProvenanceLabel, RiskTier
from agent_firewall.core.models import Decision, Finding, Verdict

SEVERITY_BASE_SCORE: dict[RiskTier, float] = {
    RiskTier.LOW: 0.2,
    RiskTier.MEDIUM: 0.5,
    RiskTier.HIGH: 0.8,
    RiskTier.CRITICAL: 1.0,
}

# Content that did not come directly from the end user scores higher for the
# same finding — see `detectors/injection.py` for the rationale.
PROVENANCE_MULTIPLIER: dict[ProvenanceLabel, float] = {
    ProvenanceLabel.USER: 1.0,
    ProvenanceLabel.SYSTEM: 0.9,
    ProvenanceLabel.ASSISTANT: 1.0,
    ProvenanceLabel.TOOL_OUTPUT: 1.2,
    ProvenanceLabel.RETRIEVED_DOC: 1.3,
    ProvenanceLabel.SUB_AGENT: 1.1,
}

# Worst-action-wins ordering for aggregating `Verdict.action` into one
# `Decision.decision`.
_ACTION_RANK: dict[DecisionAction, int] = {
    DecisionAction.ALLOW: 0,
    DecisionAction.ALLOW_WITH_MODIFICATIONS: 1,
    DecisionAction.REQUIRE_USER_CONFIRMATION: 2,
    DecisionAction.DENY: 3,
}


def finding_score(finding: Finding, provenance: ProvenanceLabel | None = None) -> float:
    """Score a single finding: severity base score * provenance multiplier,
    capped at 1.0."""

    base = SEVERITY_BASE_SCORE[finding.severity]
    multiplier = PROVENANCE_MULTIPLIER.get(provenance, 1.0) if provenance is not None else 1.0
    return min(base * multiplier, 1.0)


def max_score(scores: Iterable[float]) -> float:
    """Aggregate per-finding scores into a single risk score (max, or 0.0 if
    there are no scores)."""

    scores = list(scores)
    return max(scores) if scores else 0.0


def aggregate(verdicts: list[Verdict]) -> Decision:
    """Reduce per-stage `Verdict`s into the final `Decision`.

    - `decision`: worst action across all verdicts (DENY > REQUIRE_USER_CONFIRMATION
      > ALLOW_WITH_MODIFICATIONS > ALLOW).
    - `risk_score`: max across verdicts.
    - `reasons` / `required_approvals` / `redactions`: union, in verdict order.
    """

    if not verdicts:
        return Decision(decision=DecisionAction.ALLOW)

    worst = max(verdicts, key=lambda v: _ACTION_RANK[v.action]).action

    reasons: list[str] = []
    required_approvals: list[str] = []
    redactions = []
    risk_score = 0.0
    redacted_content: str | None = None

    for verdict in verdicts:
        for reason in verdict.reasons:
            if reason not in reasons:
                reasons.append(reason)
        for approval in verdict.required_approvals:
            if approval not in required_approvals:
                required_approvals.append(approval)
        redactions.extend(verdict.redactions)
        risk_score = max(risk_score, verdict.risk_score)
        if verdict.redacted_content is not None:
            redacted_content = verdict.redacted_content

    return Decision(
        decision=worst,
        reasons=reasons,
        risk_score=risk_score,
        required_approvals=required_approvals,
        redactions=redactions,
        redacted_content=redacted_content,
    )
