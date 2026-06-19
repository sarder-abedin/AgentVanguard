"""Verifies the LangGraph + AgentVanguard wiring end-to-end without a live
LLM: a `ScriptedChatModel` plays back a fixed sequence of tool calls, and
this script asserts AgentVanguard actually intervenes at each boundary.

Run from the repo root:

    pip install -e ".[demo]"
    python examples/langgraph_gui_demo/smoke_test.py
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from typing import Any

from pydantic import PrivateAttr

DEMO_DIR = Path(__file__).parent
sys.path.insert(0, str(DEMO_DIR))

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402

from agentvanguard import AgentVanguard  # noqa: E402

from graph import build_graph  # noqa: E402

CONFIG_PATH = str(DEMO_DIR / "agentvanguard.yaml")


class ScriptedChatModel(BaseChatModel):
    """Deterministic stand-in for a real LLM: plays back `responses` in
    order, repeating the last one if invoked more times than scripted."""

    responses: list[AIMessage]
    _index: int = PrivateAttr(default=0)

    @property
    def _llm_type(self) -> str:
        return "scripted-chat-model"

    def bind_tools(self, tools: Any, *, tool_choice: str | None = None, **kwargs: Any) -> "ScriptedChatModel":
        return self

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any) -> ChatResult:
        message = self.responses[min(self._index, len(self.responses) - 1)]
        self._index += 1
        return ChatResult(generations=[ChatGeneration(message=message)])


def _tool_call(name: str, args: dict, call_id: str) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": call_id}])


def _run_scenario(name: str, responses: list[AIMessage], user_text: str) -> list[dict]:
    firewall = AgentVanguard.from_config(CONFIG_PATH)
    model = ScriptedChatModel(responses=responses)
    graph = build_graph(firewall, model)
    session_id = f"smoke-{name}-{uuid.uuid4()}"

    result = graph.invoke(
        {"messages": [HumanMessage(content=user_text)], "decisions": [], "session_id": session_id}
    )
    print(f"\n=== {name} ===")
    for record in result["decisions"]:
        print(f"  [{record['stage']}] tool={record['tool']!r} -> {record['action']} ({record['reasons']})")
    for message in result["messages"]:
        print(f"  {type(message).__name__}: {message.content!r}")
    return result["decisions"]


def main() -> None:
    os.makedirs(DEMO_DIR / "logs", exist_ok=True)

    # 1. SSRF: the LLM calls check_status_page with an internal/metadata URL.
    decisions = _run_scenario(
        "ssrf",
        [_tool_call("check_status_page", {"url": "http://169.254.169.254/latest/meta-data/"}, "call_1")],
        "Is the vendor's internal status endpoint up? Check http://169.254.169.254/latest/meta-data/",
    )
    assert any(d["stage"] == "tool_call_guard" and d["action"] == "DENY" for d in decisions), "expected SSRF DENY"

    # 2. High-risk tool requiring approval: send_email, auto_deny -> DENY-equivalent block.
    decisions = _run_scenario(
        "send_email_requires_approval",
        [_tool_call("send_email", {"to": "alice@example.com", "body": "Refund processed."}, "call_2")],
        "Email alice@example.com to tell her the refund was processed.",
    )
    assert any(
        d["stage"] == "tool_call_guard" and d["action"] == "REQUIRE_USER_CONFIRMATION" for d in decisions
    ), "expected send_email REQUIRE_USER_CONFIRMATION"

    # 3. DLP: a tool result containing a credit-card number should be redacted.
    decisions = _run_scenario(
        "dlp_redaction",
        [
            _tool_call("lookup_order", {"order_id": "1003"}, "call_3"),
            AIMessage(content="Your order 1003 was shipped; the card on file is 4111 1111 1111 1111."),
        ],
        "What's the status of order 1003?",
    )
    assert any(
        d["stage"] == "output_guard(tool_result)" and d["action"] == "ALLOW_WITH_MODIFICATIONS" for d in decisions
    ), "expected tool-result DLP redaction"
    assert any(
        d["stage"] == "output_guard" and d["action"] == "ALLOW_WITH_MODIFICATIONS" for d in decisions
    ), "expected final-reply DLP redaction"

    # 4. Repetition limit: the same lookup_order call repeated past max_repeated_calls (3).
    firewall = AgentVanguard.from_config(CONFIG_PATH)
    session_id = f"smoke-repetition-{uuid.uuid4()}"
    blocked = False
    for i in range(6):
        model = ScriptedChatModel(
            responses=[
                _tool_call("lookup_order", {"order_id": "1001"}, f"call_loop_{i}"),
                AIMessage(content=f"Order 1001 status, attempt {i}."),
            ]
        )
        graph = build_graph(firewall, model)
        result = graph.invoke(
            {
                "messages": [HumanMessage(content="What's the status of order 1001?")],
                "decisions": [],
                "session_id": session_id,
            }
        )
        if any(
            d["action"] == "DENY" and "repeated_calls" in " ".join(d["reasons"]).lower()
            for d in result["decisions"]
        ):
            blocked = True
            print(f"\n=== repetition_limit ===\n  blocked on attempt {i + 1}")
            break
    assert blocked, "expected repeated identical tool calls to eventually be DENY'd"

    print("\nAll smoke-test scenarios passed.")


if __name__ == "__main__":
    main()
