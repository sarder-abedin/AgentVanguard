"""Core pydantic models shared by the engine, policy evaluator, guards, and
every integration surface (SDK, tool-broker, ASGI middleware, sidecar).

These models are the contract: every integration surface builds a
`PolicyInput` and receives a `Decision` back from `Engine.authorize()`.
"""

from __future__ import annotations

from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from agentvanguard.core.enums import (
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
    """Who (or what, on behalf of whom) is performing the action.

    Optional on `PolicyInput.actor` — set when the integration surface has
    end-user identity available (e.g. an authenticated HTTP request), used by
    `ToolManifest.allowed_callers`/workflow scoping checks and recorded in
    audit events for traceability.
    """

    # Stable identifier for the human/service the request is on behalf of.
    user_id: str
    # Multi-tenant deployments: which tenant/organization this request
    # belongs to, for tenant-scoped policy or audit segregation.
    tenant_id: str | None = None
    # Authorization roles the actor holds (e.g. "admin", "support_agent"),
    # available to policy rules that need role-based checks.
    roles: list[str] = Field(default_factory=list)
    auth_strength: str | None = None  # e.g. "mfa" | "password" | "service_account"


class AgentIdentity(BaseModel):
    """Which agent/workflow is making the request.

    Distinct from `Actor`: `Actor` is the human/service principal, while
    `AgentIdentity` is the specific agent acting on their behalf. The
    tool-call guard checks `AgentIdentity.name` against
    `ToolManifest.allowed_callers` and the relevant workflow's
    `allowed_agents`.
    """

    # The agent's registered name, matched against `allowed_callers` and
    # `WorkflowConfig.allowed_agents`.
    name: str
    # The workflow this agent belongs to. Used as a fallback for
    # `PolicyInput.workflow` when the caller does not set it explicitly (see
    # `guards/tool_guard.py:evaluate`).
    workflow: str | None = None


class ToolManifest(BaseModel):
    """Declares what a tool does and how risky it is, used by the policy
    engine and tool-call guard to decide whether/how a call is authorized."""

    # Unique tool identifier; matched against `PolicyInput.tool` to look up
    # the manifest for an incoming tool call (`Engine`/`AgentVanguard`
    # maintain a `name -> ToolManifest` registry).
    name: str
    # Human-readable description; informational only (not used in policy
    # decisions), useful for audit/UI display.
    description: str = ""
    # What kind of operation the tool performs (read/write/execute/...);
    # drives which argument-level checks the tool-call guard applies (e.g.
    # command-injection checks only for `ActionType.EXECUTE`).
    action_type: ActionType
    # The real-world consequence of calling the tool; drives the egress
    # allow-list check (`EXTERNAL_COMMUNICATION`) in the tool-call guard.
    side_effect: SideEffect = SideEffect.NONE
    # Overall riskiness of this tool; feeds the base risk score
    # (`policy/risk.py:SEVERITY_BASE_SCORE`) and determines whether
    # high/critical-tier calls triggered by untrusted content are escalated
    # to `REQUIRE_USER_CONFIRMATION`.
    risk_tier: RiskTier = RiskTier.MEDIUM
    # Whether the tool's effect can be undone. Informational/config-time flag
    # (e.g. surfaced via the CLI's `_ACTION_TYPE_DEFAULTS`) — not directly
    # branched on inside the tool-call guard itself, but typically paired
    # with `IRREVERSIBLE_CHANGE`/higher `risk_tier` for tools that can't be.
    reversible: bool = True
    # If True, every call to this tool is escalated to
    # `REQUIRE_USER_CONFIRMATION` regardless of risk_tier or findings —
    # used for tools that should always have a human in the loop.
    requires_approval: bool = False
    allowed_callers: list[str] = Field(default_factory=list)  # empty = any agent
    # Optional JSON Schema; tool-call arguments are validated against this
    # with `jsonschema.validate` before any other argument-level check runs
    # (a mismatch is a hard-stop `SCHEMA_VIOLATION` -> `DENY`).
    input_schema: dict[str, Any] | None = None
    # Free-form bag for integration-specific metadata not modeled elsewhere;
    # ignored by the engine/guards themselves.
    extra: dict[str, Any] = Field(default_factory=dict)


class ContentItem(BaseModel):
    """A single unit of content with an attached trust label.

    `PolicyInput.content` is either a plain `str` (trust unspecified/assumed
    uniform) or a `list[ContentItem]`, letting a caller mix trust levels
    within one ingress/output check — e.g. a user message concatenated with
    retrieved-document text, where only the latter should score as
    `RETRIEVED_DOC` provenance for injection-risk purposes.
    """

    text: str
    provenance: ProvenanceLabel
    # Optional identifier for where this content came from (e.g. a document
    # ID or tool-call ID), useful for audit/debugging; not consulted by
    # policy logic itself.
    source_id: str | None = None


class Message(BaseModel):
    """Normalized chat message, used when callers pass a full message list
    (e.g. proxy/middleware modes) instead of a single string."""

    role: Literal["system", "user", "assistant", "tool"]
    content: str
    # Optional name (e.g. the tool name for a `role="tool"` message, or a
    # specific speaker in a multi-agent transcript).
    name: str | None = None


class ToolCall(BaseModel):
    """Represents one proposed/executed tool invocation.

    Used by callers that need to describe a tool call as data (rather than
    via `PolicyInput.tool`/`arguments` directly) — e.g. validating a batch of
    planned tool calls ahead of execution. `triggering_provenance` records
    which untrusted content (if any) led to this call being proposed, mirror
    of the provenance set the tool-call guard inspects via
    `_triggering_provenance(policy_input)` to decide whether a high-risk tool
    call needs `REQUIRE_USER_CONFIRMATION`.
    """

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    triggering_provenance: list[ProvenanceLabel] = Field(default_factory=list)


class Finding(BaseModel):
    """A single detector hit.

    Detectors (`detectors/`) and guards (`guards/`) emit zero or more
    `Finding`s while evaluating a `PolicyInput`; a `Verdict` collects all
    findings from one guard stage, and `policy/risk.py:finding_score` turns
    each finding's `severity` (+ optional provenance) into a numeric score
    that feeds `Verdict.risk_score`.
    """

    # Which specific check fired (see `FindingType` for the full catalog of
    # what each value means and where it's raised).
    type: FindingType
    # Identifier of the detector/check that produced this finding (e.g.
    # `"tool_guard:ssrf"`, `"session_guard:repetition"`) — useful for
    # tracing a finding back to the exact code path in audit logs.
    detector: str
    severity: RiskTier
    # Human-readable explanation, surfaced in `Verdict.reasons` /
    # `Decision.reasons` and audit events.
    message: str
    # Optional (start, end) character offset into the original content where
    # the match occurred, for highlighting/redaction purposes.
    span: tuple[int, int] | None = None


class Redaction(BaseModel):
    """Describes one piece of content the output guard replaced before
    returning it to the caller.

    Collected into `Verdict.redactions`/`Decision.redactions` alongside the
    actual sanitized text in `redacted_content`, so callers/auditors can see
    *what kind* of data was redacted (and how many times) without the
    original sensitive value being included in the decision itself.
    """

    # Name/label of the field or finding category that was redacted (e.g.
    # corresponds to a `Finding.type` value like "pii" or "secret").
    field: str
    type: FindingType
    # The placeholder text substituted in place of the original sensitive
    # value (defaults to a generic redaction marker).
    replacement: str = "[REDACTED]"


class Verdict(BaseModel):
    """The result of a single guard stage.

    `Engine.authorize()` runs the guard(s) applicable to
    `PolicyInput.action`, each producing one `Verdict`; `policy/risk.py:aggregate`
    then reduces the resulting `Verdict` list into one final `Decision` using
    worst-action-wins semantics (see `DecisionAction`).
    """

    # Which guard (or the policy evaluator) produced this verdict.
    stage: GuardStage
    # This stage's recommended action; combined with other stages' actions
    # via worst-action-wins to produce the final `Decision.decision`.
    action: DecisionAction
    risk_score: float = 0.0
    findings: list[Finding] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    # Names of tools/approvals that must be confirmed by the configured
    # `ApprovalProvider` before this stage's action can proceed (populated
    # when `action == REQUIRE_USER_CONFIRMATION`).
    required_approvals: list[str] = Field(default_factory=list)
    redactions: list[Redaction] = Field(default_factory=list)
    # The sanitized version of the content this guard evaluated, if it
    # rewrote anything (e.g. the output guard substitutes redaction markers
    # for detected PII/secrets). `None` means this stage made no changes.
    redacted_content: str | None = None
    # If this verdict was produced by a config-defined match-dict rule
    # (`GuardStage.POLICY`), the id of the rule that fired — `None` for
    # built-in guard checks. Lets audit logs point back to the exact YAML
    # rule responsible for a decision.
    rule_id: str | None = None


class Decision(BaseModel):
    """The aggregate decision returned to the caller for one `PolicyInput`.

    This is the return value of `Engine.authorize()` and the type every
    integration surface (SDK, tool broker, ASGI middleware, sidecar routes)
    ultimately hands back to its caller. Produced by reducing the `Verdict`
    list from all guards that ran via `policy/risk.py:aggregate`.
    """

    # Final worst-action-wins outcome across all guard stages that ran.
    decision: DecisionAction
    # Union of every contributing `Verdict.reasons`, in verdict order,
    # explaining why this decision was reached.
    reasons: list[str] = Field(default_factory=list)
    # Max risk score across all contributing verdicts.
    risk_score: float = 0.0
    required_approvals: list[str] = Field(default_factory=list)
    redactions: list[Redaction] = Field(default_factory=list)
    # Sanitized content to use in place of the original, if any guard
    # rewrote it (e.g. DLP redaction on output, or ingress normalization).
    # Integration surfaces (see `firewall.py`) substitute this for the
    # original text whenever it is not `None`.
    redacted_content: str | None = None
    # Unique id for this decision, auto-generated per call. Written to the
    # audit log (`AuditEvent.trace_id`) and returned to callers so a blocked
    # request (`VanguardBlockedError`) or any decision can be looked back up
    # later (see the CLI's `explain <trace_id>` command).
    trace_id: str = Field(default_factory=lambda: str(uuid4()))


class SessionState(BaseModel):
    """Tracks cumulative, per-session usage for runtime-limit enforcement.

    Resolved by the engine per `PolicyInput.session_id` (via `SessionStore`,
    in-memory or Redis-backed) or passed explicitly as
    `PolicyInput.session_state`. The session guard
    (`guards/session_guard.py`) compares these counters against
    `config.runtime_limits.max_*` on every action (not just tool calls) to
    deny requests once a session's budget is exhausted, and the engine
    updates these fields after each `authorize()` call.
    """

    session_id: str
    # Number of `Engine.authorize()` calls made so far in this session
    # (incremented unconditionally by the engine after every call,
    # regardless of the resulting decision); compared against
    # `runtime_limits.max_steps`.
    step_count: int = 0
    # Number of `ActionKind.TOOL_CALL` actions seen so far; compared against
    # `runtime_limits.max_tool_calls`.
    tool_call_count: int = 0
    # Wall-clock time elapsed since the session started; compared against
    # `runtime_limits.max_runtime_seconds`. Unlike `step_count`/
    # `tool_call_count`, the engine does not compute this itself — callers
    # that track session duration/cost externally set it via
    # `PolicyInput.session_state`.
    elapsed_seconds: float = 0.0
    # Cumulative estimated dollar cost attributed to this session; compared
    # against `runtime_limits.max_cost_usd`. Same caveat as
    # `elapsed_seconds` — populated by the caller, not the engine.
    cost_usd: float = 0.0
    # Rolling history of `session_guard.call_hash(tool, arguments)` values
    # for prior tool calls in this session that were *not* denied, appended
    # to by the engine after each tool-call decision. The session guard
    # counts how many times the *current* call's hash already appears here
    # to detect an agent stuck repeating an identical tool call beyond
    # `runtime_limits.max_repeated_calls` (`FindingType.REPETITION_LOOP`).
    recent_tool_call_hashes: list[str] = Field(default_factory=list)


class PolicyInput(BaseModel):
    """The single input type accepted by `Engine.authorize()`.

    Every integration surface (SDK `firewall.py`, tool broker, ASGI
    middleware, sidecar routes) builds one of these per request/action and
    passes it to `Engine.authorize()`, which dispatches on `action` to the
    matching guard(s) and returns a `Decision`. Not every field is relevant
    to every `action` value — e.g. `tool`/`arguments` only matter for
    `ActionKind.TOOL_CALL`.
    """

    # What is being authorized; determines which guard(s) run.
    action: ActionKind
    # Who the request is on behalf of, if known.
    actor: Actor | None = None
    # Which agent is making the request, if known.
    agent: AgentIdentity | None = None
    # Workflow name for workflow-scoped policy (e.g.
    # `WorkflowConfig.allowed_tools`); falls back to `agent.workflow` if unset
    # (see `guards/tool_guard.py:evaluate`).
    workflow: str | None = None
    # Name of the tool being called; required (looked up against the
    # registered `ToolManifest`s) when `action == ActionKind.TOOL_CALL`.
    tool: str | None = None
    # Arguments for the tool call; validated against
    # `ToolManifest.input_schema` and scanned for SSRF/path-traversal/
    # command-injection/egress/secrets by the tool-call guard.
    arguments: dict[str, Any] | None = None
    # The content being checked for `ingress`/`output` actions: either a
    # plain string, or a list of `ContentItem`s carrying mixed provenance
    # labels (see `ContentItem`). Also consulted by the tool-call guard to
    # determine whether a tool call was triggered by untrusted content.
    content: list[ContentItem] | str | None = None
    # Identifies the session for runtime-limit/repetition tracking; used to
    # look up (or create) the corresponding `SessionState` via `SessionStore`
    # if `session_state` is not supplied directly.
    session_id: str | None = None
    # Explicit session state to use instead of resolving one from
    # `session_id` via the configured `SessionStore` — lets callers that
    # already track their own session counters bypass the store.
    session_state: SessionState | None = None
