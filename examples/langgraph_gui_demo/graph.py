"""LangGraph wiring for the demo: ingress guard -> agent (LLM) -> tool guard
-> output guard, all mediated by a single `AgentVanguard` instance.

The graph deliberately does **not** use `langgraph.prebuilt.ToolNode`: that
helper only re-raises most exceptions (it only catches `ToolInvocationError`
by default) and gives no access to the `Decision` AgentVanguard produced for
a blocked call. The custom `_tools_node` below is the one place that calls
`firewall.authorize(action="tool_call")` and `firewall.check_output(...)` per
tool call, so every `Decision` -- ALLOW or otherwise -- can be surfaced to
the GUI's decision panel.

`build_graph(firewall, chat_model, agent_identity=None)` takes the chat model
as a dependency so it can be swapped for a deterministic scripted model in
`smoke_test.py`, without touching graph logic.

Entry scripts (`app.py`, `smoke_test.py`) add this directory to `sys.path`
before importing `tools`/`graph` as top-level modules -- `streamlit run`
executes a script with no package context, so relative imports would fail.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AnyMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from agentvanguard import AgentIdentity, AgentVanguard
from agentvanguard.core.enums import ActionKind, DecisionAction
from agentvanguard.core.models import PolicyInput

from tools import build_tools

SYSTEM_PROMPT = (
    "You are a customer support assistant for an online store. You can look "
    "up orders, send emails to customers, and check a vendor's status page. "
    "Use tools when they help answer the user's request."
)

DEFAULT_AGENT = AgentIdentity(name="support_agent", workflow="customer_support")

_BLOCKED_ACTIONS = (DecisionAction.DENY, DecisionAction.REQUIRE_USER_CONFIRMATION)


class DemoState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]
    decisions: Annotated[list[dict], operator.add]
    session_id: str


def _decision_record(stage: str, decision: Any, tool: str | None = None) -> dict:
    return {
        "stage": stage,
        "tool": tool,
        "action": decision.decision.value,
        "reasons": list(decision.reasons),
        "risk_score": decision.risk_score,
        "trace_id": decision.trace_id,
    }


def build_graph(
    firewall: AgentVanguard,
    chat_model: BaseChatModel,
    agent_identity: AgentIdentity | None = None,
):
    """Returns a compiled LangGraph graph wired to `firewall` and
    `chat_model`. `agent_identity` defaults to the demo's `support_agent`
    (workflow `customer_support`, matching `agentvanguard.yaml`)."""

    agent_identity = agent_identity or DEFAULT_AGENT
    tools = build_tools()
    tools_by_name = {t.name: t for t in tools}
    bound_model = chat_model.bind_tools(tools)

    def ingress_guard(state: DemoState) -> dict:
        last_human = state["messages"][-1]
        decision = firewall.authorize(
            PolicyInput(
                action=ActionKind.INGRESS,
                agent=agent_identity,
                content=last_human.content,
                session_id=state["session_id"],
            )
        )
        record = _decision_record("ingress_guard", decision)

        if decision.decision in _BLOCKED_ACTIONS:
            reasons = "; ".join(decision.reasons) or "no reason given"
            blocked_reply = AIMessage(
                content=f"[blocked by AgentVanguard ingress guard: {decision.decision.value}] {reasons}"
            )
            return {"decisions": [record], "messages": [blocked_reply]}

        if decision.redacted_content is not None and decision.redacted_content != last_human.content:
            sanitized = last_human.model_copy(update={"content": decision.redacted_content})
            sanitized.id = last_human.id
            return {"decisions": [record], "messages": [sanitized]}

        return {"decisions": [record]}

    def ingress_router(state: DemoState) -> str:
        last_message = state["messages"][-1]
        if isinstance(last_message, AIMessage):
            return END
        return "agent"

    def agent_node(state: DemoState) -> dict:
        history = [SystemMessage(content=SYSTEM_PROMPT), *state["messages"]]
        response = bound_model.invoke(history)
        return {"messages": [response]}

    def tools_router(state: DemoState) -> str:
        last_message = state["messages"][-1]
        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "tools"
        return "output_guard"

    def tools_node(state: DemoState) -> dict:
        last_message = state["messages"][-1]
        tool_messages: list[ToolMessage] = []
        records: list[dict] = []

        for call in last_message.tool_calls:
            name, args, call_id = call["name"], call["args"], call["id"]

            call_decision = firewall.authorize(
                PolicyInput(
                    action=ActionKind.TOOL_CALL,
                    agent=agent_identity,
                    tool=name,
                    arguments=args,
                    session_id=state["session_id"],
                )
            )
            records.append(_decision_record("tool_call_guard", call_decision, tool=name))

            if call_decision.decision in _BLOCKED_ACTIONS:
                reasons = "; ".join(call_decision.reasons) or "no reason given"
                content = f"[blocked by AgentVanguard tool guard: {call_decision.decision.value}] {reasons}"
                tool_messages.append(ToolMessage(content=content, tool_call_id=call_id, name=name))
                continue

            tool = tools_by_name[name]
            result = str(tool.invoke(args))

            result_decision = firewall.check_output(result, session_id=state["session_id"])
            records.append(_decision_record("output_guard(tool_result)", result_decision, tool=name))

            if result_decision.decision in _BLOCKED_ACTIONS:
                reasons = "; ".join(result_decision.reasons) or "no reason given"
                content = f"[blocked by AgentVanguard output guard: {result_decision.decision.value}] {reasons}"
            elif result_decision.redacted_content is not None:
                content = result_decision.redacted_content
            else:
                content = result

            tool_messages.append(ToolMessage(content=content, tool_call_id=call_id, name=name))

        return {"decisions": records, "messages": tool_messages}

    def output_guard(state: DemoState) -> dict:
        last_message = state["messages"][-1]
        if not isinstance(last_message, AIMessage):
            return {}

        decision = firewall.check_output(str(last_message.content), session_id=state["session_id"])
        record = _decision_record("output_guard", decision)

        if decision.decision in _BLOCKED_ACTIONS:
            reasons = "; ".join(decision.reasons) or "no reason given"
            blocked_reply = AIMessage(
                content=f"[blocked by AgentVanguard output guard: {decision.decision.value}] {reasons}"
            )
            return {"decisions": [record], "messages": [blocked_reply]}

        if decision.redacted_content is not None and decision.redacted_content != last_message.content:
            sanitized = last_message.model_copy(update={"content": decision.redacted_content})
            sanitized.id = last_message.id
            return {"decisions": [record], "messages": [sanitized]}

        return {"decisions": [record]}

    graph = StateGraph(DemoState)
    graph.add_node("ingress_guard", ingress_guard)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tools_node)
    graph.add_node("output_guard", output_guard)

    graph.add_edge(START, "ingress_guard")
    graph.add_conditional_edges("ingress_guard", ingress_router, {"agent": "agent", END: END})
    graph.add_conditional_edges("agent", tools_router, {"tools": "tools", "output_guard": "output_guard"})
    graph.add_edge("tools", "agent")
    graph.add_edge("output_guard", END)

    return graph.compile()
