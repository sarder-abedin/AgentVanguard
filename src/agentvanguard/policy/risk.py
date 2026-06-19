"""Deterministic risk scoring and `Verdict` -> `Decision` aggregation.

These are the only two numeric/aggregation rules in the engine — every guard
scores its findings with `finding_score`, and `Engine.authorize()` reduces
the resulting `Verdict[]` to one `Decision` with `aggregate`.
"""

from __future__ import annotations

from collections.abc import Iterable

from agentvanguard.core.enums import DecisionAction, ProvenanceLabel, RiskTier
from agentvanguard.core.models import Decision, Finding, Verdict

# Base score for a finding purely as a function of its `RiskTier` severity,
# before any provenance adjustment is applied. This is the "how bad is this
# *kind* of finding in isolation" component of the scoring formula below.
SEVERITY_BASE_SCORE: dict[RiskTier, float] = {
    RiskTier.LOW: 0.2,
    RiskTier.MEDIUM: 0.5,
    RiskTier.HIGH: 0.8,
    RiskTier.CRITICAL: 1.0,
}

# Content that did not come directly from the end user scores higher for the
# same finding — see `detectors/injection.py` for the rationale.
#
# This is the "how much do we trust the *source* of the content that
# triggered the finding" component of the scoring formula. Multipliers > 1.0
# amplify the base score for less-trusted provenance (e.g. a prompt-injection
# pattern found inside a retrieved document is more dangerous than the same
# pattern typed directly by the end user, because the user presumably did not
# intend to attack their own session); multipliers <= 1.0 leave/dampen it for
# more-trusted provenance.
PROVENANCE_MULTIPLIER: dict[ProvenanceLabel, float] = {
    ProvenanceLabel.USER: 1.0,
    ProvenanceLabel.SYSTEM: 0.9,
    ProvenanceLabel.ASSISTANT: 1.0,
    ProvenanceLabel.TOOL_OUTPUT: 1.2,
    ProvenanceLabel.RETRIEVED_DOC: 1.3,
    ProvenanceLabel.SUB_AGENT: 1.1,
}

# Worst-action-wins ordering for aggregating `Verdict.action` into one
# `Decision.decision`. Higher rank = more restrictive = wins when combining
# multiple actions, so DENY (3) always beats REQUIRE_USER_CONFIRMATION (2),
# which always beats ALLOW_WITH_MODIFICATIONS (1), which always beats
# ALLOW (0). This dict is only an implementation detail of `worst_action`
# below (`max(..., key=...)` needs an orderable rank); the public ordering
# contract is documented on `worst_action` and `aggregate`.
_ACTION_RANK: dict[DecisionAction, int] = {
    DecisionAction.ALLOW: 0,
    DecisionAction.ALLOW_WITH_MODIFICATIONS: 1,
    DecisionAction.REQUIRE_USER_CONFIRMATION: 2,
    DecisionAction.DENY: 3,
}


def finding_score(finding: Finding, provenance: ProvenanceLabel | None = None) -> float:
    """Score a single finding: severity base score * provenance multiplier,
    capped at 1.0.

    Formula: ``score = min(SEVERITY_BASE_SCORE[finding.severity] * PROVENANCE_MULTIPLIER[provenance], 1.0)``.
    If `provenance` is not supplied (the common case — most guards call this
    without knowing/caring about provenance), the multiplier defaults to 1.0,
    i.e. the score is just the severity base score unmodified.

    Worked example: a `RiskTier.HIGH` finding (base score 0.8) detected in
    content whose provenance is `ProvenanceLabel.RETRIEVED_DOC` (multiplier
    1.3) scores ``min(0.8 * 1.3, 1.0) = min(1.04, 1.0) = 1.0`` — the
    multiplier pushes it past 1.0, so it is clamped to the maximum. The same
    finding with no provenance override, or with `ProvenanceLabel.USER`
    (multiplier 1.0), scores ``0.8 * 1.0 = 0.8`` — unmodified. The cap at 1.0
    keeps every individual finding's score within the same [0.0, 1.0] range
    regardless of how many multipliers stack, so scores from different guards
    remain comparable.
    """

    base = SEVERITY_BASE_SCORE[finding.severity]
    multiplier = PROVENANCE_MULTIPLIER.get(provenance, 1.0) if provenance is not None else 1.0
    return min(base * multiplier, 1.0)


def max_score(scores: Iterable[float]) -> float:
    """Aggregate per-finding scores into a single risk score (max, or 0.0 if
    there are no scores).

    Risk scores are deliberately aggregated by `max`, not by sum or average:
    a single CRITICAL finding should make the whole `Verdict` read as
    critical-risk even if it is accompanied by nine LOW findings — summing
    would let many small/benign findings drown out one severe one, and
    averaging has the same problem. Taking the max means the worst single
    finding always determines the stage's reported risk score.
    """

    scores = list(scores)
    return max(scores) if scores else 0.0


def worst_action(actions: Iterable[DecisionAction]) -> DecisionAction:
    """The worst (highest-priority) action among `actions` (DENY >
    REQUIRE_USER_CONFIRMATION > ALLOW_WITH_MODIFICATIONS > ALLOW), or `ALLOW`
    if `actions` is empty. Used both by `aggregate` (per-`Verdict`) and by
    callers that need to combine several `Decision`s, e.g. `/v1/validate-plan`.

    Implementation: ranks each action via `_ACTION_RANK` and returns the
    action with the highest rank. This is the "worst-action-wins" rule
    referenced throughout the engine: if *any* guard stage or rule says
    DENY, the combined result is DENY no matter what every other stage said;
    if nothing says DENY but something says REQUIRE_USER_CONFIRMATION, the
    combined result is REQUIRE_USER_CONFIRMATION; and so on down the
    priority order. An empty `actions` iterable (e.g. no verdicts at all)
    is treated as the most permissive case and returns ALLOW.
    """

    actions = list(actions)
    if not actions:
        return DecisionAction.ALLOW
    return max(actions, key=lambda a: _ACTION_RANK[a])


def aggregate(verdicts: list[Verdict]) -> Decision:
    """Reduce per-stage `Verdict`s into the final `Decision`.

    - `decision`: worst action across all verdicts (DENY > REQUIRE_USER_CONFIRMATION
      > ALLOW_WITH_MODIFICATIONS > ALLOW).
    - `risk_score`: max across verdicts.
    - `reasons` / `required_approvals` / `redactions`: union, in verdict order.

    Worked example: suppose `PolicyEvaluator.evaluate()` produced two
    `Verdict`s for one `PolicyInput` — a `tool_call_guard` verdict with
    `action=ALLOW`, `risk_score=0.3`, and a `session_guard` verdict with
    `action=REQUIRE_USER_CONFIRMATION`, `risk_score=0.6`, `reasons=["rate
    limit nearly exceeded"]`. `aggregate` walks both verdicts:
    `worst_action` sees `[ALLOW, REQUIRE_USER_CONFIRMATION]` and picks
    `REQUIRE_USER_CONFIRMATION` (rank 2 > rank 0); `risk_score` becomes
    `max(0.3, 0.6) = 0.6`; `reasons` becomes `["rate limit nearly
    exceeded"]` (deduplicated union, in verdict order); `required_approvals`
    and `redactions` are unioned the same way. The resulting `Decision` is
    `Decision(decision=REQUIRE_USER_CONFIRMATION, risk_score=0.6,
    reasons=["rate limit nearly exceeded"], ...)` — even though the tool-call
    guard itself was happy to ALLOW, the session guard's stricter verdict
    wins overall.
    """

    if not verdicts:
        return Decision(decision=DecisionAction.ALLOW)

    # Step 1: worst-action-wins across every stage's verdict (see
    # `worst_action` above) — this becomes the final `decision`.
    worst = worst_action(v.action for v in verdicts)

    reasons: list[str] = []
    required_approvals: list[str] = []
    redactions = []
    risk_score = 0.0
    redacted_content: str | None = None

    # Step 2: walk every verdict once and accumulate the remaining fields.
    # `reasons`/`required_approvals` are deduplicated (preserving first-seen
    # order) since multiple stages may report the same reason/tool;
    # `redactions` are concatenated as-is (duplicates are harmless — they
    # just describe redactions already applied to the content);
    # `risk_score` takes the max across stages, same rationale as
    # `max_score` above (the worst single stage determines overall risk);
    # `redacted_content`, if set by more than one verdict, ends up holding
    # whichever verdict set it last (stages are expected to operate on
    # independent content, so this is not expected to collide in practice).
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
