"""`PolicyEvaluator.evaluate()` — the single dispatch point from
`PolicyInput.action` to guard stages, plus custom `rules:` escalation.

Returns `list[Verdict]`; `Engine.authorize()` reduces this to one `Decision`
via `policy.risk.aggregate`.
"""

from __future__ import annotations

from agentvanguard.config.schema import Config
from agentvanguard.core.enums import ActionKind, GuardStage
from agentvanguard.core.models import PolicyInput, SessionState, ToolManifest, Verdict
from agentvanguard.detectors.registry import DetectorRegistry
from agentvanguard.guards import input_guard, output_guard, session_guard, tool_guard
from agentvanguard.policy.matcher import MatchContext, matches


class PolicyEvaluator:
    """Dispatches a `PolicyInput` to the appropriate guard stage(s) and
    evaluates any custom `rules:` from config."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def evaluate(
        self,
        policy_input: PolicyInput,
        detectors: DetectorRegistry,
        tool_manifests: dict[str, ToolManifest],
        session_state: SessionState,
    ) -> list[Verdict]:
        """Run every guard stage applicable to `policy_input.action` and
        return all the `Verdict`s produced, unreduced.

        Dispatch is purely a function of `policy_input.action`
        (`ActionKind`):

        - `ActionKind.INGRESS` and `ActionKind.MODEL_REQUEST` both route to
          `input_guard.evaluate`. They are treated identically here because
          both represent content arriving *into* the system from an
          untrusted or semi-trusted source before any model/tool acts on
          it — `INGRESS` is the original end-user input, `MODEL_REQUEST` is
          a request being sent to the underlying LLM (e.g. including
          retrieved context) — and both need the same prompt-injection/PII/
          secret scanning that `input_guard` performs.
        - `ActionKind.TOOL_CALL` routes to `tool_guard.evaluate`, which also
          needs `tool_manifests` (to look up the manifest for
          `policy_input.tool`) since tool-call authorization depends on
          tool-specific config (schema, risk tier, allowed callers, etc.)
          that the other guards don't need.
        - `ActionKind.OUTPUT` routes to `output_guard.evaluate`, which
          applies DLP/redaction to content leaving the system.
        - Every action kind — regardless of which (if any) branch above
          matched — *also* always runs `session_guard.evaluate`, appended
          unconditionally after the if/elif chain. Session-level limits
          (rate limits, repetition detection, step counts) apply across the
          whole session irrespective of what kind of action just happened,
          so this call sits outside the per-action dispatch.

        After the guard-stage verdicts are collected, `_evaluate_rules` runs
        the user's custom `rules:` (if any) against the combined findings/
        risk score and appends any additional `Verdict`s they produce. The
        full, unreduced list is returned; `Engine.authorize()` is
        responsible for calling `policy.risk.aggregate` to turn this list
        into one `Decision`.
        """

        verdicts: list[Verdict] = []

        if policy_input.action in (ActionKind.INGRESS, ActionKind.MODEL_REQUEST):
            verdicts.append(input_guard.evaluate(policy_input, self.config, detectors))
        elif policy_input.action == ActionKind.TOOL_CALL:
            verdicts.append(tool_guard.evaluate(policy_input, self.config, detectors, tool_manifests))
        elif policy_input.action == ActionKind.OUTPUT:
            verdicts.append(output_guard.evaluate(policy_input, self.config, detectors))

        # Always runs, for every action kind: session-level runtime limits
        # (rate limiting, repetition detection, step/tool-call counts) are
        # orthogonal to which specific action just occurred.
        verdicts.append(session_guard.evaluate(policy_input, self.config, session_state))

        # Custom rules from config see the findings/risk score produced by
        # the guard stages above, and can add further escalating verdicts.
        verdicts.extend(self._evaluate_rules(policy_input, verdicts))

        return verdicts

    def _evaluate_rules(self, policy_input: PolicyInput, verdicts: list[Verdict]) -> list[Verdict]:
        """Evaluate every `rules:` entry from config against the findings/risk
        score produced by the guard stage(s) above, returning one `Verdict`
        per matching rule (or `[]` if there are no rules configured, or none
        match).

        This lets operators layer custom, declarative escalation logic
        (`config.rules`, evaluated via `policy.matcher.matches`) on top of
        the built-in guards without writing code: e.g. "if a `tool_call` in
        workflow X is made by an actor without role Y, require confirmation"
        or "if risk_score >= 0.7, deny outright". Each matching rule
        contributes its own `Verdict` (stage=`GuardStage.POLICY`) carrying
        the rule's configured `action`, so it participates in the same
        worst-action-wins aggregation as every other guard's verdict.
        """

        if not self.config.rules:
            return []

        # Flatten every finding from every guard-stage verdict produced so
        # far, and take the max risk score across them — this is exactly the
        # `MatchContext` that `policy.matcher.matches` needs to evaluate
        # `finding_types_any` / `risk_score_gte` match keys.
        findings = [finding for verdict in verdicts for finding in verdict.findings]
        risk_score = max((verdict.risk_score for verdict in verdicts), default=0.0)
        ctx = MatchContext(policy_input=policy_input, findings=findings, risk_score=risk_score)

        rule_verdicts: list[Verdict] = []
        for rule in self.config.rules:
            if matches(rule.match, ctx):
                # Build a verdict for this matching rule: its `action` comes
                # straight from the rule's config (the operator decides
                # whether a match means DENY, REQUIRE_USER_CONFIRMATION,
                # etc.); `risk_score` is carried through unchanged so the
                # rule doesn't lower the score already established by the
                # guards; `reasons` falls back to a generic "matched custom
                # rule" message if the rule didn't configure its own
                # `reason`, so the audit trail always has something
                # human-readable to show.
                rule_verdicts.append(
                    Verdict(
                        stage=GuardStage.POLICY,
                        action=rule.action,
                        risk_score=risk_score,
                        reasons=[rule.reason or f"matched custom rule '{rule.id or '<unnamed>'}'"],
                        rule_id=rule.id,
                    )
                )
        return rule_verdicts
