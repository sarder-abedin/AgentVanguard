"""Unit tests for `agent_firewall.guards.session_guard`."""

from __future__ import annotations

from agent_firewall.config.schema import Config
from agent_firewall.core.enums import ActionKind, DecisionAction, FindingType
from agent_firewall.core.models import PolicyInput, SessionState
from agent_firewall.guards import session_guard
from agent_firewall.guards.session_guard import call_hash


def test_within_limits_is_allowed() -> None:
    config = Config()
    session_state = SessionState(session_id="s-1")
    policy_input = PolicyInput(action=ActionKind.INGRESS, content="hello")

    verdict = session_guard.evaluate(policy_input, config, session_state)

    assert verdict.action == DecisionAction.ALLOW
    assert verdict.findings == []


def test_max_steps_exceeded_denies() -> None:
    config = Config()
    session_state = SessionState(session_id="s-1", step_count=config.runtime_limits.max_steps + 1)
    policy_input = PolicyInput(action=ActionKind.INGRESS, content="hello")

    verdict = session_guard.evaluate(policy_input, config, session_state)

    assert verdict.action == DecisionAction.DENY
    assert any(f.type == FindingType.BUDGET_EXCEEDED for f in verdict.findings)


def test_max_tool_calls_exceeded_denies() -> None:
    config = Config()
    session_state = SessionState(session_id="s-1", tool_call_count=config.runtime_limits.max_tool_calls + 1)
    policy_input = PolicyInput(action=ActionKind.TOOL_CALL, tool="lookup_order", arguments={})

    verdict = session_guard.evaluate(policy_input, config, session_state)

    assert verdict.action == DecisionAction.DENY
    assert any(f.type == FindingType.BUDGET_EXCEEDED for f in verdict.findings)


def test_max_runtime_seconds_exceeded_denies() -> None:
    config = Config()
    session_state = SessionState(session_id="s-1", elapsed_seconds=config.runtime_limits.max_runtime_seconds + 1)
    policy_input = PolicyInput(action=ActionKind.INGRESS, content="hello")

    verdict = session_guard.evaluate(policy_input, config, session_state)

    assert verdict.action == DecisionAction.DENY
    assert any(f.type == FindingType.BUDGET_EXCEEDED for f in verdict.findings)


def test_max_cost_usd_exceeded_denies() -> None:
    config = Config()
    session_state = SessionState(session_id="s-1", cost_usd=config.runtime_limits.max_cost_usd + 1)
    policy_input = PolicyInput(action=ActionKind.INGRESS, content="hello")

    verdict = session_guard.evaluate(policy_input, config, session_state)

    assert verdict.action == DecisionAction.DENY
    assert any(f.type == FindingType.BUDGET_EXCEEDED for f in verdict.findings)


def test_repeated_identical_tool_call_denies_after_limit() -> None:
    config = Config()
    policy_input = PolicyInput(action=ActionKind.TOOL_CALL, tool="lookup_order", arguments={"order_id": "1234"})
    current_hash = call_hash("lookup_order", {"order_id": "1234"})

    session_state = SessionState(
        session_id="s-1",
        recent_tool_call_hashes=[current_hash] * config.runtime_limits.max_repeated_calls,
    )

    verdict = session_guard.evaluate(policy_input, config, session_state)

    assert verdict.action == DecisionAction.DENY
    assert any(f.type == FindingType.REPETITION_LOOP for f in verdict.findings)


def test_repeated_call_within_limit_is_allowed() -> None:
    config = Config()
    policy_input = PolicyInput(action=ActionKind.TOOL_CALL, tool="lookup_order", arguments={"order_id": "1234"})
    current_hash = call_hash("lookup_order", {"order_id": "1234"})

    session_state = SessionState(
        session_id="s-1",
        recent_tool_call_hashes=[current_hash] * (config.runtime_limits.max_repeated_calls - 1),
    )

    verdict = session_guard.evaluate(policy_input, config, session_state)

    assert verdict.action == DecisionAction.ALLOW
    assert verdict.findings == []


def test_call_hash_is_stable_and_order_independent() -> None:
    first = call_hash("lookup_order", {"a": 1, "b": 2})
    second = call_hash("lookup_order", {"b": 2, "a": 1})

    assert first == second


def test_call_hash_differs_for_different_arguments() -> None:
    first = call_hash("lookup_order", {"order_id": "1234"})
    second = call_hash("lookup_order", {"order_id": "5678"})

    assert first != second
