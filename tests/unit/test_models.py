"""Unit tests for `agentvanguard.core.models`."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentvanguard.core.enums import (
    ActionKind,
    ActionType,
    DecisionAction,
    FindingType,
    GuardStage,
    ProvenanceLabel,
    RiskTier,
)
from agentvanguard.core.models import (
    Actor,
    AgentIdentity,
    ContentItem,
    Decision,
    Finding,
    PolicyInput,
    Redaction,
    SessionState,
    ToolManifest,
    Verdict,
)


def test_decision_defaults_to_allow_with_generated_trace_id() -> None:
    decision = Decision(decision=DecisionAction.ALLOW)

    assert decision.decision == DecisionAction.ALLOW
    assert decision.reasons == []
    assert decision.risk_score == 0.0
    assert decision.required_approvals == []
    assert decision.redactions == []
    assert decision.redacted_content is None
    assert decision.trace_id  # non-empty, generated UUID string


def test_decision_trace_ids_are_unique() -> None:
    first = Decision(decision=DecisionAction.ALLOW)
    second = Decision(decision=DecisionAction.ALLOW)

    assert first.trace_id != second.trace_id


def test_verdict_defaults() -> None:
    verdict = Verdict(stage=GuardStage.INPUT, action=DecisionAction.ALLOW)

    assert verdict.findings == []
    assert verdict.reasons == []
    assert verdict.required_approvals == []
    assert verdict.redactions == []
    assert verdict.redacted_content is None
    assert verdict.rule_id is None


def test_tool_manifest_requires_action_type() -> None:
    with pytest.raises(ValidationError):
        ToolManifest(name="send_email")  # type: ignore[call-arg]


def test_tool_manifest_defaults() -> None:
    manifest = ToolManifest(name="send_email", action_type=ActionType.SEND_EXTERNAL)

    assert manifest.risk_tier == RiskTier.MEDIUM
    assert manifest.reversible is True
    assert manifest.requires_approval is False
    assert manifest.allowed_callers == []
    assert manifest.input_schema is None
    assert manifest.extra == {}


def test_policy_input_accepts_bare_string_content() -> None:
    policy_input = PolicyInput(action=ActionKind.INGRESS, content="hello")

    assert policy_input.content == "hello"
    assert policy_input.action == ActionKind.INGRESS


def test_policy_input_accepts_content_item_list() -> None:
    items = [
        ContentItem(text="hello", provenance=ProvenanceLabel.USER),
        ContentItem(text="retrieved", provenance=ProvenanceLabel.RETRIEVED_DOC, source_id="doc-1"),
    ]
    policy_input = PolicyInput(action=ActionKind.MODEL_REQUEST, content=items)

    assert isinstance(policy_input.content, list)
    assert policy_input.content[1].source_id == "doc-1"


def test_finding_and_redaction_round_trip_json() -> None:
    finding = Finding(
        type=FindingType.PII,
        detector="pii:email",
        severity=RiskTier.LOW,
        message="email address detected",
        span=(0, 5),
    )
    redaction = Redaction(field="content", type=FindingType.PII)

    dumped_finding = finding.model_dump(mode="json")
    dumped_redaction = redaction.model_dump(mode="json")

    assert dumped_finding["span"] == [0, 5]
    assert dumped_finding["severity"] == "low"
    assert dumped_redaction["replacement"] == "[REDACTED]"


def test_actor_and_agent_identity_defaults() -> None:
    actor = Actor(user_id="u-1")
    agent = AgentIdentity(name="support_agent")

    assert actor.roles == []
    assert actor.tenant_id is None
    assert agent.workflow is None


def test_session_state_defaults() -> None:
    state = SessionState(session_id="s-1")

    assert state.step_count == 0
    assert state.tool_call_count == 0
    assert state.elapsed_seconds == 0.0
    assert state.cost_usd == 0.0
    assert state.recent_tool_call_hashes == []
