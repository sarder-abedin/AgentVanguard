"""Unit tests for `agent_firewall.policy.*` (matcher, risk aggregation, and
`PolicyEvaluator` dispatch / custom rules)."""

from __future__ import annotations

import pytest

from agent_firewall.config.schema import Config, RuleConfig
from agent_firewall.core.enums import (
    ActionKind,
    ActionType,
    DecisionAction,
    FindingType,
    GuardStage,
    ProvenanceLabel,
    RiskTier,
)
from agent_firewall.core.errors import PolicyError
from agent_firewall.core.models import (
    Actor,
    AgentIdentity,
    ContentItem,
    Finding,
    PolicyInput,
    SessionState,
    ToolManifest,
    Verdict,
)
from agent_firewall.detectors.registry import DetectorRegistry
from agent_firewall.policy.evaluator import PolicyEvaluator
from agent_firewall.policy.matcher import MatchContext, matches
from agent_firewall.policy.risk import aggregate, finding_score, max_score, worst_action

# ---------------------------------------------------------------------------
# risk scoring + aggregation
# ---------------------------------------------------------------------------


def test_max_score_empty_returns_zero() -> None:
    assert max_score([]) == 0.0


def test_finding_score_capped_at_one() -> None:
    finding = Finding(type=FindingType.SECRET, detector="secrets:aws", severity=RiskTier.CRITICAL, message="x")

    score = finding_score(finding, ProvenanceLabel.RETRIEVED_DOC)  # 1.0 * 1.3 -> capped at 1.0

    assert score == 1.0


def test_aggregate_empty_verdicts_allows() -> None:
    decision = aggregate([])

    assert decision.decision == DecisionAction.ALLOW


def test_aggregate_worst_action_wins() -> None:
    verdicts = [
        Verdict(stage=GuardStage.INPUT, action=DecisionAction.ALLOW, risk_score=0.2),
        Verdict(stage=GuardStage.SESSION, action=DecisionAction.DENY, risk_score=0.9, reasons=["budget exceeded"]),
    ]

    decision = aggregate(verdicts)

    assert decision.decision == DecisionAction.DENY
    assert decision.risk_score == 0.9
    assert "budget exceeded" in decision.reasons


def test_aggregate_propagates_redacted_content() -> None:
    verdicts = [
        Verdict(
            stage=GuardStage.OUTPUT,
            action=DecisionAction.ALLOW_WITH_MODIFICATIONS,
            redacted_content="redacted text",
        ),
        Verdict(stage=GuardStage.SESSION, action=DecisionAction.ALLOW),
    ]

    decision = aggregate(verdicts)

    assert decision.redacted_content == "redacted text"


def test_worst_action_empty_is_allow() -> None:
    assert worst_action([]) == DecisionAction.ALLOW


def test_worst_action_picks_highest_priority() -> None:
    actions = [DecisionAction.ALLOW, DecisionAction.ALLOW_WITH_MODIFICATIONS, DecisionAction.REQUIRE_USER_CONFIRMATION]

    assert worst_action(actions) == DecisionAction.REQUIRE_USER_CONFIRMATION
    assert worst_action([*actions, DecisionAction.DENY]) == DecisionAction.DENY


# ---------------------------------------------------------------------------
# matcher
# ---------------------------------------------------------------------------


def test_matches_empty_dict_always_matches() -> None:
    ctx = MatchContext(policy_input=PolicyInput(action=ActionKind.INGRESS, content="hi"))

    assert matches({}, ctx) is True


def test_matches_tool() -> None:
    policy_input = PolicyInput(action=ActionKind.TOOL_CALL, tool="send_email")
    ctx = MatchContext(policy_input=policy_input)

    assert matches({"tool": "send_email"}, ctx) is True
    assert matches({"tool": "lookup_order"}, ctx) is False


def test_matches_workflow_falls_back_to_agent_workflow() -> None:
    policy_input = PolicyInput(
        action=ActionKind.TOOL_CALL,
        tool="send_email",
        agent=AgentIdentity(name="support_agent", workflow="customer_support"),
    )
    ctx = MatchContext(policy_input=policy_input)

    assert matches({"workflow": "customer_support"}, ctx) is True
    assert matches({"workflow": "finance"}, ctx) is False


def test_matches_actor_tenant_id() -> None:
    policy_input = PolicyInput(action=ActionKind.TOOL_CALL, tool="send_email", actor=Actor(user_id="u1", tenant_id="acme"))
    ctx = MatchContext(policy_input=policy_input)

    assert matches({"actor.tenant_id": "acme"}, ctx) is True
    assert matches({"actor.tenant_id": "other"}, ctx) is False


def test_matches_actor_roles_any() -> None:
    policy_input = PolicyInput(
        action=ActionKind.TOOL_CALL, tool="send_email", actor=Actor(user_id="u1", roles=["support", "admin"])
    )
    ctx = MatchContext(policy_input=policy_input)

    assert matches({"actor.roles_any": ["admin"]}, ctx) is True
    assert matches({"actor.roles_any": ["billing"]}, ctx) is False


def test_matches_provenance_in() -> None:
    policy_input = PolicyInput(
        action=ActionKind.MODEL_REQUEST,
        content=[ContentItem(text="x", provenance=ProvenanceLabel.RETRIEVED_DOC)],
    )
    ctx = MatchContext(policy_input=policy_input)

    assert matches({"provenance_in": ["retrieved_doc"]}, ctx) is True
    assert matches({"provenance_in": ["tool_output"]}, ctx) is False


def test_matches_finding_types_any() -> None:
    finding = Finding(type=FindingType.PROMPT_INJECTION, detector="injection:x", severity=RiskTier.HIGH, message="x")
    ctx = MatchContext(policy_input=PolicyInput(action=ActionKind.INGRESS, content="x"), findings=[finding])

    assert matches({"finding_types_any": ["prompt_injection"]}, ctx) is True
    assert matches({"finding_types_any": ["secret"]}, ctx) is False


def test_matches_risk_score_gte() -> None:
    ctx = MatchContext(policy_input=PolicyInput(action=ActionKind.INGRESS, content="x"), risk_score=0.9)

    assert matches({"risk_score_gte": 0.5}, ctx) is True
    assert matches({"risk_score_gte": 0.95}, ctx) is False


def test_matches_unknown_key_raises_policy_error() -> None:
    ctx = MatchContext(policy_input=PolicyInput(action=ActionKind.INGRESS, content="x"))

    with pytest.raises(PolicyError):
        matches({"bogus_key": "value"}, ctx)


# ---------------------------------------------------------------------------
# PolicyEvaluator dispatch
# ---------------------------------------------------------------------------


def test_evaluate_ingress_dispatches_to_input_guard() -> None:
    config = Config()
    detectors = DetectorRegistry.from_config(config)
    evaluator = PolicyEvaluator(config)
    session_state = SessionState(session_id="s-1")
    policy_input = PolicyInput(action=ActionKind.INGRESS, content="hello")

    verdicts = evaluator.evaluate(policy_input, detectors, {}, session_state)

    stages = {v.stage for v in verdicts}
    assert GuardStage.INPUT in stages
    assert GuardStage.SESSION in stages


def test_evaluate_tool_call_dispatches_to_tool_guard() -> None:
    config = Config()
    detectors = DetectorRegistry.from_config(config)
    evaluator = PolicyEvaluator(config)
    session_state = SessionState(session_id="s-1")
    tool_manifests = {
        "lookup_order": ToolManifest(name="lookup_order", action_type=ActionType.READ, risk_tier=RiskTier.LOW)
    }
    policy_input = PolicyInput(action=ActionKind.TOOL_CALL, tool="lookup_order", arguments={})

    verdicts = evaluator.evaluate(policy_input, detectors, tool_manifests, session_state)

    stages = {v.stage for v in verdicts}
    assert GuardStage.TOOL_CALL in stages
    assert GuardStage.SESSION in stages


def test_evaluate_output_dispatches_to_output_guard() -> None:
    config = Config()
    detectors = DetectorRegistry.from_config(config)
    evaluator = PolicyEvaluator(config)
    session_state = SessionState(session_id="s-1")
    policy_input = PolicyInput(action=ActionKind.OUTPUT, content="hello")

    verdicts = evaluator.evaluate(policy_input, detectors, {}, session_state)

    stages = {v.stage for v in verdicts}
    assert GuardStage.OUTPUT in stages
    assert GuardStage.SESSION in stages


def test_custom_rule_escalates_low_risk_tool_call() -> None:
    config = Config(
        tools={"lookup_order": {"action_type": "read", "risk_tier": "low"}},
        rules=[
            RuleConfig(
                id="escalate_lookup",
                match={"tool": "lookup_order"},
                action=DecisionAction.REQUIRE_USER_CONFIRMATION,
                reason="manual escalation",
            )
        ],
    )
    detectors = DetectorRegistry.from_config(config)
    evaluator = PolicyEvaluator(config)
    session_state = SessionState(session_id="s-1")
    tool_manifests = config.tool_manifests()
    policy_input = PolicyInput(action=ActionKind.TOOL_CALL, tool="lookup_order", arguments={})

    verdicts = evaluator.evaluate(policy_input, detectors, tool_manifests, session_state)
    decision = aggregate(verdicts)

    assert decision.decision == DecisionAction.REQUIRE_USER_CONFIRMATION
    assert "manual escalation" in decision.reasons
    assert any(v.stage == GuardStage.POLICY and v.rule_id == "escalate_lookup" for v in verdicts)


def test_custom_rule_does_not_match_other_tools() -> None:
    config = Config(
        tools={
            "lookup_order": {"action_type": "read", "risk_tier": "low"},
            "send_email": {"action_type": "send_external", "risk_tier": "low"},
        },
        rules=[
            RuleConfig(
                id="escalate_lookup",
                match={"tool": "lookup_order"},
                action=DecisionAction.REQUIRE_USER_CONFIRMATION,
            )
        ],
    )
    detectors = DetectorRegistry.from_config(config)
    evaluator = PolicyEvaluator(config)
    session_state = SessionState(session_id="s-1")
    tool_manifests = config.tool_manifests()
    policy_input = PolicyInput(action=ActionKind.TOOL_CALL, tool="send_email", arguments={})

    verdicts = evaluator.evaluate(policy_input, detectors, tool_manifests, session_state)
    decision = aggregate(verdicts)

    assert decision.decision == DecisionAction.ALLOW
    assert not any(v.stage == GuardStage.POLICY for v in verdicts)
