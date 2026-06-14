"""Request models for the convenience endpoints (`/v1/check-ingress`,
`/v1/check-model-request`, `/v1/authorize-tool-call`, `/v1/check-output`).

Each is a thin, action-specific subset of `PolicyInput`'s fields; the route
handlers fill in the fixed `action` field and call `Engine.authorize()` via
`PolicyInput` directly. `/v1/authorize` accepts a full `PolicyInput` as-is.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from agent_firewall.core.enums import DecisionAction
from agent_firewall.core.models import Actor, AgentIdentity, ContentItem, Decision, SessionState


class IngressRequest(BaseModel):
    content: list[ContentItem] | str
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class ModelRequestRequest(BaseModel):
    content: list[ContentItem] | str
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class ToolCallRequest(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    content: list[ContentItem] | str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class OutputRequest(BaseModel):
    content: str
    destination: str = "plain"
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class CompileContextRequest(BaseModel):
    """A list of RAG-retrieved content blocks (each with its own
    `provenance`) to scan before they are assembled into the model's context
    window. Equivalent to an `action=ingress` check over `items`."""

    items: list[ContentItem]
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class MemoryReadRequest(BaseModel):
    """Content retrieved from a memory/vector store, about to be injected
    into context. Always evaluated as `retrieved_doc` provenance regardless
    of the original source -- this is where memory-poisoning content is
    caught by the input guard's injection detector."""

    content: str
    source_id: str | None = None
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class MemoryWriteRequest(BaseModel):
    """Content about to be persisted to a memory/vector store. Runs the
    output guard (DLP) so secrets/PII are redacted before being stored."""

    content: str
    source_id: str | None = None
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class PlanStep(BaseModel):
    """One planned tool call. `content` carries `triggering_provenance` --
    see `guards/tool_guard.py`'s provenance-escalation check."""

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    content: list[ContentItem] | None = None


class ValidatePlanRequest(BaseModel):
    """A multi-step tool-call plan to validate *before* executing any of it."""

    plan: list[PlanStep]
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class ValidatePlanResponse(BaseModel):
    """`overall` is the worst-action-wins `Decision.decision` across `steps`,
    one per `ValidatePlanRequest.plan` entry, in order."""

    overall: DecisionAction
    steps: list[Decision]
