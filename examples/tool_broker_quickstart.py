"""Tool-broker quick-start: `@firewall.tool`, `wrap_tool`, and the
`VanguardBlockedError` flow.

Run from the repo root:

    python examples/tool_broker_quickstart.py
"""

from __future__ import annotations

from pathlib import Path

from agentvanguard import ActionType, AgentVanguard, AgentIdentity, RiskTier, SideEffect, ToolManifest
from agentvanguard.core.errors import VanguardBlockedError

CONFIG_PATH = str(Path(__file__).parent / "agentvanguard.yaml")

firewall = AgentVanguard.from_config(CONFIG_PATH)

SUPPORT_AGENT = AgentIdentity(name="support_agent", workflow="customer_support")
CONTEXT = {"agent": SUPPORT_AGENT, "session_id": "tool-broker-demo"}


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
    return f"Order {order_id} shipped to alice@example.com, status: delivered."


# `send_email` is already declared under `tools:` in agentvanguard.yaml
# (risk_tier: high, requires_approval: true) -- look it up by name instead of
# redeclaring its manifest.
def _send_email(to: str, body: str) -> str:
    print(f"[would send email to {to}]: {body}")
    return "sent"


send_email = firewall.wrap_tool("send_email", _send_email)


def main() -> None:
    # ALLOW: low-risk tool, registered caller.
    print("lookup_order ->", lookup_order(order_id="1234", _context=CONTEXT))

    # send_email requires approval, and the default
    # `firewall.approval_provider: auto_deny` never grants it, so
    # REQUIRE_USER_CONFIRMATION resolves to DENY -> VanguardBlockedError.
    try:
        send_email(to="alice@example.com", body="Your refund has been processed.", _context=CONTEXT)
    except VanguardBlockedError as exc:
        print("send_email blocked:", exc)


if __name__ == "__main__":
    main()
