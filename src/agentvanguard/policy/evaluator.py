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
        verdicts: list[Verdict] = []

        if policy_input.action in (ActionKind.INGRESS, ActionKind.MODEL_REQUEST):
            verdicts.append(input_guard.evaluate(policy_input, self.config, detectors))
        elif policy_input.action == ActionKind.TOOL_CALL:
            verdicts.append(tool_guard.evaluate(policy_input, self.config, detectors, tool_manifests))
        elif policy_input.action == ActionKind.OUTPUT:
            verdicts.append(output_guard.evaluate(policy_input, self.config, detectors))

        verdicts.append(session_guard.evaluate(policy_input, self.config, session_state))

        verdicts.extend(self._evaluate_rules(policy_input, verdicts))

        return verdicts

    def _evaluate_rules(self, policy_input: PolicyInput, verdicts: list[Verdict]) -> list[Verdict]:
        if not self.config.rules:
            return []

        findings = [finding for verdict in verdicts for finding in verdict.findings]
        risk_score = max((verdict.risk_score for verdict in verdicts), default=0.0)
        ctx = MatchContext(policy_input=policy_input, findings=findings, risk_score=risk_score)

        rule_verdicts: list[Verdict] = []
        for rule in self.config.rules:
            if matches(rule.match, ctx):
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
