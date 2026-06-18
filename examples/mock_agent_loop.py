"""Mock agent loop: ingress -> repeated tool calls -> egress, with session
tracking.

Demonstrates wiring `wrap_agent` (ingress/egress) and `wrap_tool` (per-call
mediation) together, and how `runtime_limits.max_repeated_calls` stops a
stuck/looping agent that keeps calling the same tool with the same
arguments.

Run from the repo root:

    python examples/mock_agent_loop.py
"""

from __future__ import annotations

from pathlib import Path

from agentvanguard import ActionType, AgentVanguard, AgentIdentity, RiskTier, SideEffect, ToolManifest
from agentvanguard.core.errors import VanguardBlockedError

CONFIG_PATH = str(Path(__file__).parent / "agentvanguard.yaml")

firewall = AgentVanguard.from_config(CONFIG_PATH)

SUPPORT_AGENT = AgentIdentity(name="support_agent", workflow="customer_support")
SESSION_ID = "mock-agent-loop-demo"
CONTEXT = {"agent": SUPPORT_AGENT, "session_id": SESSION_ID}


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
    return f"Order {order_id}: status=delivered"


class StuckAgent:
    """Simulates an agent that keeps re-issuing the same tool call -- a
    common symptom of a confused or looping agent."""

    def run(self, user_message: str) -> str:
        results = []
        for _ in range(6):
            try:
                results.append(lookup_order(order_id="1234", _context=CONTEXT))
            except VanguardBlockedError as exc:
                results.append(f"blocked: {exc.decision.decision.value}")
                break
        return "; ".join(results)


def main() -> None:
    safe_agent = firewall.wrap_agent(StuckAgent())
    print(safe_agent.run("What's the status of order 1234?", _context=CONTEXT))


if __name__ == "__main__":
    main()
