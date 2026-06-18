"""Session guard: runtime-limit and repetition-loop checks.

Runs for every action (not just `tool_call`) against the resolved
`SessionState` (from `SessionStore` or `PolicyInput.session_state`):

- `session_state.step_count/tool_call_count/elapsed_seconds/cost_usd` over
  the corresponding `config.runtime_limits.max_*` -> `DENY` (`BUDGET_EXCEEDED`).
- For `tool_call` actions, an identical `(tool, arguments)` call repeated
  beyond `config.runtime_limits.max_repeated_calls` -> `DENY`
  (`REPETITION_LOOP`). "Identical" is a stable hash of `(tool, arguments)`,
  tracked in `SessionState.recent_tool_call_hashes` by the engine.
"""

from __future__ import annotations

import hashlib
import json

from agentvanguard.config.schema import Config
from agentvanguard.core.enums import ActionKind, DecisionAction, FindingType, GuardStage, RiskTier
from agentvanguard.core.models import Finding, PolicyInput, SessionState, Verdict
from agentvanguard.policy.risk import finding_score, max_score


def call_hash(tool: str, arguments: dict | None) -> str:
    """Stable hash of a `(tool, arguments)` pair, used for repetition
    detection. JSON-based (rather than `hash()`) so it is stable across
    processes and serializable in `SessionState.recent_tool_call_hashes`."""

    payload = json.dumps({"tool": tool, "arguments": arguments or {}}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def evaluate(policy_input: PolicyInput, config: Config, session_state: SessionState) -> Verdict:
    """Run the session guard and return its `Verdict`."""

    limits = config.runtime_limits
    findings: list[Finding] = []

    if session_state.step_count > limits.max_steps:
        findings.append(
            _budget_finding(
                f"step_count {session_state.step_count} exceeds max_steps {limits.max_steps}"
            )
        )
    if session_state.tool_call_count > limits.max_tool_calls:
        findings.append(
            _budget_finding(
                f"tool_call_count {session_state.tool_call_count} exceeds "
                f"max_tool_calls {limits.max_tool_calls}"
            )
        )
    if session_state.elapsed_seconds > limits.max_runtime_seconds:
        findings.append(
            _budget_finding(
                f"elapsed_seconds {session_state.elapsed_seconds} exceeds "
                f"max_runtime_seconds {limits.max_runtime_seconds}"
            )
        )
    if session_state.cost_usd > limits.max_cost_usd:
        findings.append(
            _budget_finding(
                f"cost_usd {session_state.cost_usd} exceeds max_cost_usd {limits.max_cost_usd}"
            )
        )

    if policy_input.action == ActionKind.TOOL_CALL and policy_input.tool:
        current_hash = call_hash(policy_input.tool, policy_input.arguments)
        repeat_count = session_state.recent_tool_call_hashes.count(current_hash) + 1
        if repeat_count > limits.max_repeated_calls:
            findings.append(
                Finding(
                    type=FindingType.REPETITION_LOOP,
                    detector="session_guard:repetition",
                    severity=RiskTier.HIGH,
                    message=(
                        f"tool '{policy_input.tool}' called with identical arguments "
                        f"{repeat_count} times, exceeding max_repeated_calls "
                        f"{limits.max_repeated_calls}"
                    ),
                )
            )

    action = DecisionAction.DENY if findings else DecisionAction.ALLOW
    risk_score = max_score(finding_score(f) for f in findings)

    return Verdict(
        stage=GuardStage.SESSION,
        action=action,
        risk_score=risk_score,
        findings=findings,
        reasons=[f.message for f in findings],
    )


def _budget_finding(message: str) -> Finding:
    return Finding(
        type=FindingType.BUDGET_EXCEEDED,
        detector="session_guard:runtime_limits",
        severity=RiskTier.HIGH,
        message=message,
    )
