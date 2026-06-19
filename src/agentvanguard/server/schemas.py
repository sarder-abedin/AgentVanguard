"""Request models for the convenience endpoints (`/v1/check-ingress`,
`/v1/check-model-request`, `/v1/authorize-tool-call`, `/v1/check-output`).

Each is a thin, action-specific subset of `PolicyInput`'s fields; the route
handlers fill in the fixed `action` field and call `Engine.authorize()` via
`PolicyInput` directly. `/v1/authorize` accepts a full `PolicyInput` as-is.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from agentvanguard.core.enums import DecisionAction
from agentvanguard.core.models import Actor, AgentIdentity, ContentItem, Decision, SessionState


class IngressRequest(BaseModel):
    """Body for `POST /v1/check-ingress`.

    `routes.check_ingress` builds a `PolicyInput(action=ActionKind.INGRESS,
    **fields)` from this directly -- `content` may be a single string or a
    list of pre-tagged `ContentItem`s (e.g. for multi-part input).
    `session_state` is accepted for schema symmetry with `PolicyInput` but is
    always dropped server-side (see `routes._data`); session state is
    resolved from the `SessionStore` by `session_id` instead.
    """

    content: list[ContentItem] | str
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class ModelRequestRequest(BaseModel):
    """Body for `POST /v1/check-model-request`.

    `routes.check_model_request` builds a `PolicyInput(action=ActionKind.
    MODEL_REQUEST, **fields)` from this directly. Same field shape as
    `IngressRequest`, but represents the fully-assembled prompt about to be
    sent to the model rather than a single piece of raw input/context.
    """

    content: list[ContentItem] | str
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class ToolCallRequest(BaseModel):
    """Body for `POST /v1/authorize-tool-call`.

    `routes.authorize_tool_call` builds a `PolicyInput(action=ActionKind.
    TOOL_CALL, **fields)` from this directly. `tool` is the tool name as
    registered in the engine's `tool_manifests`; `arguments` are the proposed
    call arguments to be schema/SSRF/path-traversal/egress/credential
    checked by `guards/tool_guard.py`; `content` (optional) carries
    triggering provenance for the provenance-escalation check.
    """

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    content: list[ContentItem] | str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class OutputRequest(BaseModel):
    """Body for `POST /v1/check-output`.

    `routes.check_output` builds a `PolicyInput(action=ActionKind.OUTPUT,
    arguments={"destination": destination}, **fields)` from this --
    `destination` is pulled out separately because `PolicyInput` carries it
    inside `arguments` rather than as a top-level field. This is the route
    that exercises the output guard's DLP/redaction, populating
    `Decision.redacted_content` when secrets/PII are found in `content`.
    """

    content: str
    destination: str = "plain"
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class CompileContextRequest(BaseModel):
    """Body for `POST /v1/compile-context`.

    A list of RAG-retrieved content blocks (each with its own
    `provenance`) to scan before they are assembled into the model's context
    window. Equivalent to an `action=ingress` check over `items`.
    `routes.compile_context` passes `items` straight through as
    `PolicyInput.content`.
    """

    items: list[ContentItem]
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class MemoryReadRequest(BaseModel):
    """Body for `POST /v1/check-memory-read`.

    Content retrieved from a memory/vector store, about to be injected
    into context. Always evaluated as `retrieved_doc` provenance regardless
    of the original source -- this is where memory-poisoning content is
    caught by the input guard's injection detector. `routes.check_memory_read`
    wraps `content`/`source_id` in a `ContentItem` and authorizes it as
    `action=ingress`.
    """

    content: str
    source_id: str | None = None
    actor: Actor | None = None
    agent: AgentIdentity | None = None
    workflow: str | None = None
    session_id: str | None = None
    session_state: SessionState | None = None


class MemoryWriteRequest(BaseModel):
    """Body for `POST /v1/check-memory-write`.

    Content about to be persisted to a memory/vector store. Runs the
    output guard (DLP) so secrets/PII are redacted before being stored.
    `routes.check_memory_write` wraps `content`/`source_id` in a `ContentItem`
    and authorizes it as `action=output` with `destination="plain"`.
    """

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
    """Body for `POST /v1/validate-plan`.

    A multi-step tool-call plan to validate *before* executing any of it.
    `routes.validate_plan` authorizes each `PlanStep` in `plan`, in order, as
    a separate `action=tool_call` `PolicyInput` (sharing this request's
    `actor`/`agent`/`workflow`/`session_id`), so session-level counters
    accumulate across steps just as they would during real execution.
    """

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
