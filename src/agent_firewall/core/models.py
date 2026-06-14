"""Core pydantic models shared by the engine, policy evaluator, guards, and
every integration surface (SDK, tool-broker, ASGI middleware, sidecar).

These models are the contract: every integration surface builds a
`PolicyInput` and receives a `Decision` back from `Engine.authorize()`.
"""

from __future__ import annotations

from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from agent_firewall.core.enums import (
    ActionKind,
    ActionType,
    DecisionAction,
    FindingType,
    GuardStage,
    ProvenanceLabel,
    RiskTier,
    SideEffect,
)


class Actor(BaseModel):
    """Who (or what, on behalf of whom) is performing the action."""

    user_id: str
    tenant_id: str | None = None
    roles: list[str] = Field(default_factory=list)
    auth_strength: str | None = None  # e.g. "mfa" | "password" | "service_account"


class AgentIdentity(BaseModel):
    """Which agent/workflow is making the request."""

    name: str
    workflow: str | None = None


class ToolManifest(BaseModel):
    """Declares what a tool does and how risky it is, used by the policy
    engine and tool-call guard to decide whether/how a call is authorized."""

    name: str
    description: str = ""
    action_type: ActionType
    side_effect: SideEffect = SideEffect.NONE
    risk_tier: RiskTier = RiskTier.MEDIUM
    reversible: bool = True
    requires_approval: bool = False
    allowed_callers: list[str] = Field(default_factory=list)  # empty = any agent
    input_schema: dict[str, Any] | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class ContentItem(BaseModel):
    """A single unit of content with an attached trust label."""

    text: str
    provenance: ProvenanceLabel
    source_id: str | None = None


class Message(BaseModel):
    """Normalized chat message, used when callers pass a full message list
    (e.g. proxy/middleware modes) instead of a single string."""

    role: Literal["system", "user", "assistant", "tool"]
    content: str
    name: str | None = None


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    triggering_provenance: list[ProvenanceLabel] = Field(default_factory=list)


class Finding(BaseModel):
    """A single detector hit."""

    type: FindingType
    detector: str
    severity: RiskTier
    message: str
    span: tuple[int, int] | None = None


class Redaction(BaseModel):
    field: str
    type: FindingType
    replacement: str = "[REDACTED]"


class Verdict(BaseModel):
    """The result of a single guard stage."""

    stage: GuardStage
    action: DecisionAction
    risk_score: float = 0.0
    findings: list[Finding] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    required_approvals: list[str] = Field(default_factory=list)
    redactions: list[Redaction] = Field(default_factory=list)
    redacted_content: str | None = None
    rule_id: str | None = None


class Decision(BaseModel):
    """The aggregate decision returned to the caller for one `PolicyInput`."""

    decision: DecisionAction
    reasons: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    required_approvals: list[str] = Field(default_factory=list)
    redactions: list[Redaction] = Field(default_factory=list)
    redacted_content: str | None = None
    trace_id: str = Field(default_factory=lambda: str(uuid4()))


class SessionState(BaseModel):
    session_id: str
    step_count: int = 0
    tool_call_count: int = 0
    elapsed_seconds: float = 0.0
    cost_usd: float = 0.0
    recent_tool_call_hashes: list[str] = Field(default_factory=list)


class PolicyInput(BaseModel):
    """The single input type accepted by `Engine.authorize()`."""

    action: ActionKind
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    tool: str | None = None
    arguments: dict[str, Any] | None = None
    content: list[ContentItem] | str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None
