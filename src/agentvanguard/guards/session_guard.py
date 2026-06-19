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
    processes and serializable in `SessionState.recent_tool_call_hashes`.

    `sort_keys=True` makes the hash independent of argument insertion order
    (so `{"a": 1, "b": 2}` and `{"b": 2, "a": 1}` hash identically, since
    they represent the same call), and `default=str` lets non-JSON-native
    argument values (e.g. a custom object) be hashed via their `str()` form
    instead of raising. Example: `call_hash("read_file", {"path": "/tmp/x"})`
    always returns the same hex digest for that exact tool+arguments pair,
    regardless of process or call order.
    """

    payload = json.dumps({"tool": tool, "arguments": arguments or {}}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def evaluate(policy_input: PolicyInput, config: Config, session_state: SessionState) -> Verdict:
    """Run the session guard and return its `Verdict`.

    Two independent families of checks are performed, and either can
    produce a `Finding` that forces the verdict to `DENY`:

    1. **Runtime/budget limits** — compares each running counter on
       `session_state` (steps taken, tool calls made, wall-clock time
       elapsed, dollars spent) against the corresponding `max_*` ceiling in
       `config.runtime_limits`. These checks run for *every* action, not
       just tool calls, because a long-running session can blow its step or
       time budget purely through ingress/output actions.
    2. **Repetition-loop detection** — only for `tool_call` actions: detects
       an agent stuck calling the exact same tool with the exact same
       arguments over and over (a classic agentic failure mode), by hashing
       the current call and counting how many times that hash already
       appears in the session's recent-call history.
    """

    limits = config.runtime_limits
    findings: list[Finding] = []

    # Budget checks: each one independently appends a Finding if the
    # corresponding running counter has exceeded its configured ceiling.
    # All four are checked (not short-circuited) so a single Verdict can
    # report every limit that was breached, not just the first one.
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
        # Hash this exact (tool, arguments) pair and count how many times it
        # already occurs in the session's rolling history of recent tool
        # calls. The "+1" accounts for the current call itself, so
        # repeat_count is "total occurrences including this one" rather than
        # "prior occurrences" — e.g. if the same call hash already appears
        # twice in history and this is a third identical call, repeat_count
        # is 3. That total is then compared against max_repeated_calls.
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

    # Any finding from either check family (budget or repetition) is a hard
    # stop for this stage: the session guard has no "warn but allow" or
    # "require confirmation" outcome, only ALLOW or DENY.
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
    """Build a `BUDGET_EXCEEDED` `Finding` for a single runtime-limit breach
    (step/tool-call count, elapsed time, or cost) with the supplied
    human-readable `message` (e.g. "step_count 51 exceeds max_steps 50")."""

    return Finding(
        type=FindingType.BUDGET_EXCEEDED,
        detector="session_guard:runtime_limits",
        severity=RiskTier.HIGH,
        message=message,
    )
