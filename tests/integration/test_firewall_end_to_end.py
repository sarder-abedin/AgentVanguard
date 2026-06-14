"""End-to-end integration tests: `AgentFirewall` -> `Engine` -> guards ->
audit, driven through `wrap_tool`/`@firewall.tool` and `authorize` directly.

Each test builds its own `AgentFirewall` from a config written to `tmp_path`
so audit logs and session state never leak between tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agent_firewall import ActionType, AgentFirewall, AgentIdentity, RiskTier, SideEffect, ToolManifest
from agent_firewall.core.enums import ActionKind, DecisionAction
from agent_firewall.core.errors import FirewallBlockedError
from agent_firewall.core.models import PolicyInput

SUPPORT_AGENT = AgentIdentity(name="support_agent", workflow="customer_support")


def _context(session_id: str) -> dict:
    return {"agent": SUPPORT_AGENT, "session_id": session_id}


def _build_firewall(tmp_path: Path, **runtime_limit_overrides: object) -> tuple[AgentFirewall, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    audit_path = tmp_path / "logs" / "audit.jsonl"

    runtime_limits = {
        "max_steps": 50,
        "max_tool_calls": 50,
        "max_runtime_seconds": 600,
        "max_cost_usd": 100,
        "max_repeated_calls": 2,
    }
    runtime_limits.update(runtime_limit_overrides)

    config = {
        "firewall": {
            "fail_closed": True,
            "default_workflow_mode": "restrictive",
            "approval_provider": "auto_deny",
        },
        "audit": {"backend": "jsonl", "path": str(audit_path), "redact_secrets": True},
        "runtime_limits": runtime_limits,
        "tool_guard": {"workspace_root": str(workspace)},
        "tools": {
            "lookup_order": {
                "action_type": "read",
                "side_effect": "internal_read",
                "risk_tier": "low",
                "allowed_callers": ["support_agent"],
            },
            "send_email": {
                "action_type": "send_external",
                "side_effect": "external_communication",
                "risk_tier": "high",
                "requires_approval": True,
                "allowed_callers": ["support_agent"],
            },
            "read_file": {
                "action_type": "read",
                "risk_tier": "low",
                "allowed_callers": ["support_agent"],
            },
            "fetch_url": {
                "action_type": "read",
                "risk_tier": "low",
                "allowed_callers": ["support_agent"],
            },
        },
        "workflows": {
            "customer_support": {
                "allowed_agents": ["support_agent"],
                "allowed_tools": ["lookup_order", "send_email", "read_file", "fetch_url"],
            }
        },
    }

    config_path = tmp_path / "agent_firewall.yaml"
    config_path.write_text(yaml.safe_dump(config))

    return AgentFirewall.from_config(str(config_path)), audit_path


def test_unknown_tool_is_denied(tmp_path: Path) -> None:
    firewall, _ = _build_firewall(tmp_path)

    decision = firewall.authorize(
        PolicyInput(action=ActionKind.TOOL_CALL, tool="delete_database", agent=SUPPORT_AGENT, arguments={})
    )

    assert decision.decision == DecisionAction.DENY
    assert any("not registered" in reason for reason in decision.reasons)


def test_high_risk_tool_requires_approval_is_blocked(tmp_path: Path) -> None:
    firewall, _ = _build_firewall(tmp_path)

    def _send_email(to: str, body: str) -> str:
        return "sent"

    send_email = firewall.wrap_tool("send_email", _send_email)

    with pytest.raises(FirewallBlockedError) as exc_info:
        send_email(to="alice@company.com", body="hi", _context=_context("s-approval"))

    decision = exc_info.value.decision
    # AutoDenyApprovalProvider never grants REQUIRE_USER_CONFIRMATION, so the
    # call is blocked -- effectively a deny -- even though the raw decision
    # value remains REQUIRE_USER_CONFIRMATION.
    assert decision.decision == DecisionAction.REQUIRE_USER_CONFIRMATION
    assert decision.required_approvals == ["send_email"]


def test_ssrf_argument_is_denied(tmp_path: Path) -> None:
    firewall, _ = _build_firewall(tmp_path)

    def _fetch_url(url: str) -> str:
        return "ok"

    fetch_url = firewall.wrap_tool("fetch_url", _fetch_url)

    with pytest.raises(FirewallBlockedError) as exc_info:
        fetch_url(url="http://169.254.169.254/latest/meta-data/", _context=_context("s-ssrf"))

    assert exc_info.value.decision.decision == DecisionAction.DENY


def test_path_traversal_argument_is_denied(tmp_path: Path) -> None:
    firewall, _ = _build_firewall(tmp_path)

    def _read_file(path: str) -> str:
        return "file contents"

    read_file = firewall.wrap_tool("read_file", _read_file)

    with pytest.raises(FirewallBlockedError) as exc_info:
        read_file(path="../../etc/passwd", _context=_context("s-path"))

    assert exc_info.value.decision.decision == DecisionAction.DENY


def test_pii_in_tool_result_is_redacted(tmp_path: Path) -> None:
    firewall, _ = _build_firewall(tmp_path)

    @firewall.tool(
        manifest=ToolManifest(
            name="lookup_order",
            action_type=ActionType.READ,
            side_effect=SideEffect.INTERNAL_READ,
            risk_tier=RiskTier.LOW,
            allowed_callers=["support_agent"],
        )
    )
    def lookup_order(order_id: str) -> str:
        return f"Order {order_id}: customer SSN on file is 123-45-6789."

    result = lookup_order(order_id="1234", _context=_context("s-pii"))

    assert "123-45-6789" not in result
    assert "[REDACTED]" in result


def test_repeated_identical_tool_call_denied_after_limit(tmp_path: Path) -> None:
    firewall, _ = _build_firewall(tmp_path, max_repeated_calls=2)

    def _lookup_order(order_id: str) -> str:
        return f"Order {order_id}: status=delivered"

    lookup_order = firewall.wrap_tool("lookup_order", _lookup_order)
    ctx = _context("s-repeat")

    assert lookup_order(order_id="1234", _context=ctx) == "Order 1234: status=delivered"
    assert lookup_order(order_id="1234", _context=ctx) == "Order 1234: status=delivered"

    with pytest.raises(FirewallBlockedError) as exc_info:
        lookup_order(order_id="1234", _context=ctx)

    decision = exc_info.value.decision
    assert decision.decision == DecisionAction.DENY
    assert any("identical arguments" in reason for reason in decision.reasons)


def test_audit_log_has_one_redacted_event_per_decision(tmp_path: Path) -> None:
    firewall, audit_path = _build_firewall(tmp_path)

    firewall.authorize(
        PolicyInput(action=ActionKind.INGRESS, content="My SSN is 123-45-6789.", session_id="s-audit")
    )
    firewall.authorize(
        PolicyInput(
            action=ActionKind.TOOL_CALL,
            tool="delete_database",
            agent=SUPPORT_AGENT,
            arguments={},
            session_id="s-audit",
        )
    )

    assert audit_path.exists()
    events = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
    assert len(events) == 2

    for event in events:
        assert {"event_id", "trace_id", "decision", "risk_score", "payload"} <= event.keys()

    ingress_event, tool_call_event = events
    payload_text = json.dumps(ingress_event["payload"])
    assert "123-45-6789" not in payload_text
    assert "[REDACTED]" in payload_text

    assert tool_call_event["decision"] == "DENY"
