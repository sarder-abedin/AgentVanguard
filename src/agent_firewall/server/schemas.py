"""Request models for the convenience endpoints (`/v1/check-ingress`,
`/v1/check-model-request`, `/v1/authorize-tool-call`, `/v1/check-output`).

Each is a thin, action-specific subset of `PolicyInput`'s fields; the route
handlers fill in the fixed `action` field and call `Engine.authorize()` via
`PolicyInput` directly. `/v1/authorize` accepts a full `PolicyInput` as-is.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from agent_firewall.core.models import Actor, AgentIdentity, ContentItem, SessionState


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
