"""Shared enums used across the engine, policy, guards, and integrations.

All enums in this module subclass `str` as well as `Enum` so their members
serialize directly as plain strings in pydantic models (`core/models.py`),
JSON audit events, and YAML config — callers can compare/construct them with
either the enum member (`RiskTier.HIGH`) or the raw string (`"high"`).
"""

from enum import Enum


class ProvenanceLabel(str, Enum):
    """Trust label attached to every piece of content flowing through the engine.

    Used on `ContentItem.provenance` (ingress/output content) and on
    `ToolCall.triggering_provenance` / checked via `_triggering_provenance`
    in `guards/tool_guard.py`. Detectors and the tool-call guard treat
    findings differently depending on where the content originated — content
    that did not come directly from the end user (tool output, retrieved
    docs, sub-agents) is scored higher for the same finding type, since it is
    more likely to carry an injected/adversarial instruction. See
    `policy/risk.py:PROVENANCE_MULTIPLIER` for the exact weighting.
    """

    # Text typed directly by the end user — the most-trusted source.
    USER = "user"
    # Text injected by the system/operator (e.g. the system prompt).
    SYSTEM = "system"
    # Text produced by the LLM/agent itself (e.g. on the way out, or echoed
    # back in as part of a multi-turn transcript).
    ASSISTANT = "assistant"
    # The return value of a tool call — untrusted, since the tool may be
    # calling out to attacker-controlled systems.
    TOOL_OUTPUT = "tool_output"
    # Content pulled in via retrieval/RAG — untrusted, classic vector for
    # indirect prompt injection.
    RETRIEVED_DOC = "retrieved_doc"
    # Content produced by another (sub-)agent in a multi-agent system —
    # untrusted relative to the top-level user/system.
    SUB_AGENT = "sub_agent"


class ActionType(str, Enum):
    """What kind of operation a tool performs.

    Set on `ToolManifest.action_type` and consulted by the tool-call guard to
    decide which argument-level checks apply: `EXECUTE` tools are checked for
    shell metacharacters (`_check_command_injection`), and `READ`/`WRITE`/
    `DELETE` tools get path-traversal checks (`_check_path_traversal`) against
    `tool_guard.workspace_root`.
    """

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    SEND_EXTERNAL = "send_external"
    DELETE = "delete"
    FINANCIAL = "financial"


class SideEffect(str, Enum):
    """The real-world consequence of a tool call.

    Set on `ToolManifest.side_effect`. Distinct from `ActionType` — two tools
    can share an `ActionType` (e.g. both `WRITE`) but have very different
    blast radius (`INTERNAL_WRITE` vs. `IRREVERSIBLE_CHANGE`). The tool-call
    guard specifically checks for `EXTERNAL_COMMUNICATION` to decide whether
    the egress allow-list (`_check_egress`) applies.
    """

    # No real-world side effect (e.g. a pure read-only computation).
    NONE = "none"
    # Reads data that stays inside the system's own trust boundary.
    INTERNAL_READ = "internal_read"
    # Writes data that stays inside the system's own trust boundary.
    INTERNAL_WRITE = "internal_write"
    # Sends data to, or receives data from, an external network endpoint —
    # triggers the egress allow-list check in the tool-call guard.
    EXTERNAL_COMMUNICATION = "external_communication"
    # Moves money or otherwise has a financial consequence.
    FINANCIAL_TRANSACTION = "financial_transaction"
    # Cannot be undone (e.g. permanent delete, sent email) — typically paired
    # with `ToolManifest.reversible = False` and a higher `risk_tier`.
    IRREVERSIBLE_CHANGE = "irreversible_change"


class RiskTier(str, Enum):
    """Coarse severity/risk bucket used throughout the engine.

    Used both as `ToolManifest.risk_tier` (how risky a tool is in general)
    and as `Finding.severity` (how severe a single detector hit is). Maps to
    a numeric base score via `policy/risk.py:SEVERITY_BASE_SCORE`
    (LOW=0.2, MEDIUM=0.5, HIGH=0.8, CRITICAL=1.0) which feeds into
    `Verdict.risk_score`/`Decision.risk_score`. `HIGH`/`CRITICAL`-tier tools
    triggered by untrusted content (see `ProvenanceLabel`) are escalated to
    `REQUIRE_USER_CONFIRMATION` by the tool-call guard even absent any
    specific finding.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionAction(str, Enum):
    """The outcome of evaluating a `PolicyInput`.

    This is both `Verdict.action` (per guard-stage outcome) and
    `Decision.decision` (the final, aggregated outcome returned to the
    caller). Aggregation across stages is "worst action wins", in the order
    declared here from least to most restrictive: `ALLOW` <
    `ALLOW_WITH_MODIFICATIONS` < `REQUIRE_USER_CONFIRMATION` < `DENY` (see
    `policy/risk.py:_ACTION_RANK`/`worst_action`).
    """

    # Permitted, unmodified.
    ALLOW = "ALLOW"
    # Permitted, but the engine altered the content/result before returning
    # it (e.g. PII/secret redaction by the output guard) — see
    # `Decision.redacted_content`.
    ALLOW_WITH_MODIFICATIONS = "ALLOW_WITH_MODIFICATIONS"
    # Not permitted outright, but escalated to a human/`ApprovalProvider` for
    # an explicit yes/no before proceeding (e.g. a high-risk tool call).
    REQUIRE_USER_CONFIRMATION = "REQUIRE_USER_CONFIRMATION"
    # Blocked outright; the action must not proceed. This is the fail-closed
    # default for unknown tools/workflows and any hard-stop finding.
    DENY = "DENY"


class FindingType(str, Enum):
    """The specific kind of issue a detector or guard found.

    Each member corresponds to one specific check somewhere in
    `detectors/` or `guards/`; the comments below name where each is raised
    so the mapping from "what fired" to "where it lives in code" is explicit.
    """

    # `detectors/injection.py` — heuristic match for a prompt-injection
    # pattern (e.g. "ignore previous instructions").
    PROMPT_INJECTION = "prompt_injection"
    # `detectors/pii.py` — personally identifiable information detected
    # (email, phone, SSN, credit card, etc.).
    PII = "pii"
    # `detectors/secrets.py` — a credential/API key/token-shaped string was
    # detected (also run over tool-call arguments by `guards/tool_guard.py`).
    SECRET = "secret"
    # `guards/tool_guard.py:_check_ssrf` — a tool argument resolves to a
    # private/loopback/link-local/reserved address (server-side request
    # forgery risk, e.g. cloud metadata endpoints).
    SSRF = "ssrf"
    # `guards/tool_guard.py:_check_path_traversal` — a path-like argument
    # normalizes to a location outside `tool_guard.workspace_root`.
    PATH_TRAVERSAL = "path_traversal"
    # `guards/tool_guard.py:_check_egress` — a tool with
    # `SideEffect.EXTERNAL_COMMUNICATION` targets a host not on the
    # configured egress allow-list.
    EGRESS_DENIED = "egress_denied"
    # `guards/tool_guard.py` — tool call arguments fail `jsonschema`
    # validation against `ToolManifest.input_schema`.
    SCHEMA_VIOLATION = "schema_violation"
    # `detectors/exfil.py` — content matches a data-exfiltration pattern
    # (e.g. instructions to send sensitive data somewhere external).
    EXFIL_PATTERN = "exfil_pattern"
    # `guards/session_guard.py` — a runtime limit (`max_steps`,
    # `max_tool_calls`, `max_runtime_seconds`, `max_cost_usd`) was exceeded
    # for the session.
    BUDGET_EXCEEDED = "budget_exceeded"
    # `guards/session_guard.py` — the same `(tool, arguments)` call was
    # repeated beyond `runtime_limits.max_repeated_calls`, indicating the
    # agent is stuck in a loop.
    REPETITION_LOOP = "repetition_loop"
    # `guards/tool_guard.py` — `PolicyInput.tool` does not match any
    # registered `ToolManifest`; this is the core fail-closed guarantee for
    # tool calls.
    UNKNOWN_TOOL = "unknown_tool"
    # `guards/tool_guard.py` — the calling agent/workflow is not permitted to
    # invoke this tool (`ToolManifest.allowed_callers`, or a workflow's
    # `allowed_tools`/`allowed_agents`).
    CALLER_NOT_ALLOWED = "caller_not_allowed"
    # `guards/tool_guard.py:_check_command_injection` — a string argument to
    # an `ActionType.EXECUTE` tool contains shell metacharacters.
    COMMAND_INJECTION = "command_injection"


class GuardStage(str, Enum):
    """Which guard (or the rule-based policy evaluator) produced a `Verdict`.

    Set on `Verdict.stage` so a `Decision`'s contributing verdicts can be
    traced back to the component that issued them; each value corresponds to
    one module under `guards/` (plus `POLICY` for match-dict rule hits from
    `policy/evaluator.py`, which can run alongside any guard).
    """

    # `guards/input_guard.py` — ingress/model_request (untrusted input)
    # checks: prompt injection, PII/secret scanning on incoming content.
    INPUT = "input_guard"
    # `guards/tool_guard.py` — tool-call authorization checks.
    TOOL_CALL = "tool_call_guard"
    # `guards/output_guard.py` — egress (outgoing content) checks and DLP
    # redaction.
    OUTPUT = "output_guard"
    # `guards/session_guard.py` — runtime-limit and repetition-loop checks,
    # evaluated for every action kind (not just tool calls).
    SESSION = "session_guard"
    # `policy/evaluator.py` — verdict produced by a config-defined match-dict
    # rule rather than a built-in guard/detector.
    POLICY = "policy"


class ActionKind(str, Enum):
    """The `action` field of a `PolicyInput` — what is being authorized.

    `Engine.authorize()` dispatches on this field to decide which guard(s)
    run for a given `PolicyInput` (see `engine.py`): `INGRESS` and `OUTPUT`
    go through the input/output guards respectively, `TOOL_CALL` goes
    through the tool-call guard, and `MODEL_REQUEST` is reserved for
    authorizing an outbound call to the LLM itself (e.g. proxy/middleware
    modes). The session guard runs for every `ActionKind`.
    """

    # A piece of untrusted content is entering the system (e.g. user message,
    # retrieved document) and needs ingress checks before reaching the model.
    INGRESS = "ingress"
    # An outbound request to the LLM itself is being authorized.
    MODEL_REQUEST = "model_request"
    # The agent/model wants to invoke a tool; routed to the tool-call guard.
    TOOL_CALL = "tool_call"
    # Content is leaving the system (e.g. the model's response to the user)
    # and needs egress checks/redaction before being returned.
    OUTPUT = "output"
