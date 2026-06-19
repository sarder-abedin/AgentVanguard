"""Pydantic schema for `agentvanguard.yaml`.

`Config` is the root model. Every section has built-in defaults so that
`Config()` (no file at all) is a valid, fail-closed configuration — this is
the fallback used by `config/loader.py` when no config file is found.

Each class below is a pydantic `BaseModel` corresponding to one top-level
(or nested) key in `agentvanguard.yaml`. Field-level validation (types,
`Literal` choices, enum membership) is handled automatically by pydantic
when `Config.model_validate(raw_dict)` is called from `config/loader.py`;
anything that *can't* be expressed as a single field's type (e.g. a
reference from one section to another) is instead checked explicitly in
`Config.validate_references()` at the bottom of this file.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from agentvanguard.core.enums import (
    ActionType,
    DecisionAction,
    ProvenanceLabel,
    RiskTier,
    SideEffect,
)
from agentvanguard.core.models import ToolManifest


class FirewallSection(BaseModel):
    """Top-level `firewall:` section: process-wide behavior switches that
    don't belong to any one guard.

    - `fail_closed`: if true (the default), unexpected errors during
      evaluation should be treated as a deny/restrict rather than allowed
      through -- the project's core fail-closed guarantee.
    - `default_workflow_mode`: governs how a `workflow` value that isn't
      declared under `workflows:` is treated -- `"restrictive"` (default)
      denies/limits it, `"permissive"` allows it through unrestricted.
    - `log_level`: passed to `observability/logging.py`'s
      `configure_logging()` by `agentvanguard serve`.
    - `approval_provider`: which `ApprovalProvider` implementation handles
      `REQUIRE_USER_CONFIRMATION` decisions -- `"auto_deny"` (default,
      fail-closed, suitable for unattended use) or `"cli_prompt"`
      (interactive, local-dev only).
    """

    fail_closed: bool = True
    default_workflow_mode: Literal["restrictive", "permissive"] = "restrictive"
    log_level: str = "INFO"
    approval_provider: Literal["auto_deny", "cli_prompt"] = "auto_deny"


class HttpBatchAuditConfig(BaseModel):
    """Optional `HttpBatchAuditSink`, used alongside (not instead of) the
    `jsonl` sink to ship audit events to a central collector.

    - `enabled`: off by default; the `jsonl` file sink is always active
      regardless of this setting.
    - `endpoint`: URL audit events are POSTed to once `batch_size` events
      have accumulated (or some other flush trigger inside the sink fires).
    - `batch_size`: number of `AuditEvent`s buffered before a batch POST.
    - `headers`: extra HTTP headers (e.g. an auth token) sent with each
      batch request.
    - `timeout`: per-request HTTP timeout, in seconds.
    """

    enabled: bool = False
    endpoint: str = ""
    batch_size: int = 50
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: float = 10.0


class AuditSection(BaseModel):
    """Top-level `audit:` section: where and how `AuditEvent`s are persisted.

    - `backend`: only `"jsonl"` is currently supported (append-only JSON
      Lines file).
    - `path`: filesystem path to the JSONL audit log; `cli/main.py`'s
      `doctor`/`explain` commands both read this field to locate the file.
    - `redact_secrets`: whether secret-like findings should be redacted
      before being written to the audit log itself (independent of the DLP
      guard's redaction of the live response).
    - `http_batch`: optional secondary sink, see `HttpBatchAuditConfig`.
    """

    backend: Literal["jsonl"] = "jsonl"
    path: str = "./logs/agentvanguard_audit.jsonl"
    redact_secrets: bool = True
    http_batch: HttpBatchAuditConfig = Field(default_factory=HttpBatchAuditConfig)


class RuntimeLimits(BaseModel):
    """Top-level `runtime_limits:` section: session-level caps enforced by
    `guards/session_guard.py` to bound how much an agent session can do.

    - `max_steps`: maximum number of `Engine.authorize()` calls (of any
      action kind) allowed within one session before further calls are
      denied/restricted.
    - `max_tool_calls`: maximum number of `action="tool_call"` calls within
      one session.
    - `max_runtime_seconds`: maximum wall-clock time a session may remain
      active.
    - `max_cost_usd`: maximum cumulative cost (e.g. LLM token spend, if the
      caller reports it) attributable to one session.
    - `max_repeated_calls`: maximum number of times the *same* tool call
      (same tool name + same arguments, see `guards/session_guard.call_hash`)
      may repeat within one session -- guards against runaway retry loops.
    """

    max_steps: int = 12
    max_tool_calls: int = 8
    max_runtime_seconds: float = 60.0
    max_cost_usd: float = 5.00
    max_repeated_calls: int = 3


class PromptInjectionSection(BaseModel):
    """Top-level `prompt_injection:` section: thresholds for the prompt-
    injection detector consumed by the input guard.

    - `enabled`: whether the detector runs at all.
    - `deny_threshold`: a detected prompt-injection confidence score at or
      above this value causes a `DENY` verdict.
    - `review_threshold`: a score at or above this value (but below
      `deny_threshold`) causes a `REQUIRE_USER_CONFIRMATION` verdict instead
      of an outright deny.
    """

    enabled: bool = True
    deny_threshold: float = 0.85
    review_threshold: float = 0.65


class DLPSection(BaseModel):
    """Top-level `dlp:` section: which categories of sensitive data the
    output guard's DLP/redaction detectors should act on.

    - `enabled`: whether DLP scanning/redaction runs at all on output.
    - `redact_emails`: whether email addresses should be redacted (off by
      default, since email addresses are often legitimate output).
    - `redact_secrets`: whether API-key/credential-shaped strings should be
      redacted.
    - `redact_credit_cards`: whether credit-card-number-shaped strings
      should be redacted.
    """

    enabled: bool = True
    redact_emails: bool = False
    redact_secrets: bool = True
    redact_credit_cards: bool = True


class ToolGuardSection(BaseModel):
    """Global defaults for the tool-call guard.

    - `workspace_root`: filesystem root used by the tool guard's
      path-traversal checks -- tool arguments that resolve to a path
      outside this root are treated as suspicious/denied.
    - `egress_allowlist`: hostnames/domains tool calls are allowed to
      reach for SSRF/egress checks, applied globally in addition to any
      per-`WorkflowConfig.egress_allowlist`.
    """

    workspace_root: str = "."
    egress_allowlist: list[str] = Field(default_factory=list)


class SessionStoreSection(BaseModel):
    """`SessionStore` backend. `in_memory` (default) is process-local;
    `redis` is shared across replicas (requires the `redis` extra).

    - `backend`: which `SessionStore` implementation `session/factory.py`
      constructs.
    - `redis_url`: connection string used only when `backend="redis"`.
    - `key_prefix`: namespacing prefix for session keys in Redis, to avoid
      collisions with other applications sharing the same Redis instance.
    - `ttl_seconds`: how long an idle session's state survives before
      expiring; `None` disables expiry.
    """

    backend: Literal["in_memory", "redis"] = "in_memory"
    redis_url: str = "redis://localhost:6379/0"
    key_prefix: str = "agentvanguard:session:"
    ttl_seconds: int | None = 3600


class ToolConfig(BaseModel):
    """A tool entry under `tools:`. Same fields as `ToolManifest` minus
    `name`, which is taken from the YAML mapping key.

    - `description`: free-text, human-readable description of what the
      tool does (not used in policy decisions, just documentation).
    - `action_type`: what kind of operation the tool performs (`read`,
      `write`, `execute`, `send_external`, `delete`, `financial`) --
      drives several default risk heuristics.
    - `side_effect`: the real-world consequence of calling the tool (e.g.
      `internal_read` vs. `irreversible_change`), used by risk scoring.
    - `risk_tier`: baseline risk tier (`low`/`medium`/`high`/`critical`)
      contributing to the aggregated risk score for any call to this tool.
    - `reversible`: whether the tool's effect can be undone -- irreversible
      tools are scored as riskier.
    - `requires_approval`: if true, any call to this tool produces (at
      least) a `REQUIRE_USER_CONFIRMATION` verdict, regardless of other
      risk factors.
    - `allowed_callers`: agent identities permitted to call this tool; a
      caller not in this list (when non-empty) is denied.
    - `input_schema`: optional JSON Schema the tool-call arguments are
      validated against by the tool guard before the call proceeds.
    - `extra`: free-form, tool-specific metadata not otherwise modeled
      (e.g. `max_rows` for a query tool) -- passed through to `ToolManifest`
      but not interpreted by the engine itself.
    """

    description: str = ""
    action_type: ActionType
    side_effect: SideEffect = SideEffect.NONE
    risk_tier: RiskTier = RiskTier.MEDIUM
    reversible: bool = True
    requires_approval: bool = False
    allowed_callers: list[str] = Field(default_factory=list)
    input_schema: dict[str, Any] | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    def to_manifest(self, name: str) -> ToolManifest:
        """Convert this config entry into a runtime `ToolManifest`,
        supplying `name` (the YAML mapping key) since `ToolConfig` itself
        doesn't carry its own name."""

        return ToolManifest(name=name, **self.model_dump())


class WorkflowConfig(BaseModel):
    """A workflow entry under `workflows:`, used to scope which
    agents/tools/egress targets are permitted when `PolicyInput.workflow`
    matches this entry's key.

    - `risk_tier`: baseline risk tier applied to all activity under this
      workflow.
    - `allowed_agents`: agent identities permitted to participate in this
      workflow; empty means no additional restriction beyond global rules.
    - `allowed_tools`: tool names permitted within this workflow -- cross-
      checked against `Config.tools` by `validate_references()` below, so a
      typo or an undeclared tool name is caught at config-load time rather
      than failing silently at runtime.
    - `egress_allowlist`: hostnames/domains tool calls within this workflow
      are allowed to reach, in addition to the global
      `ToolGuardSection.egress_allowlist`.
    """

    risk_tier: RiskTier = RiskTier.MEDIUM
    allowed_agents: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    egress_allowlist: list[str] = Field(default_factory=list)


class RuleConfig(BaseModel):
    """An escalation-only custom rule, evaluated last by the policy
    evaluator. `match` keys are documented in `policy/matcher.py`.

    - `id`: optional human-readable identifier for the rule, useful in
      audit logs/error messages; not required to be unique by the schema
      itself.
    - `match`: a dict of match-dict conditions (see `policy/matcher.py` for
      the supported keys) that determine whether this rule applies to a
      given `PolicyInput`.
    - `action`: the `DecisionAction` to apply when `match` is satisfied.
      Custom rules are "escalation-only," meaning they can only make the
      outcome stricter than what the rest of the pipeline already decided,
      never loosen it (enforced by the aggregation/worst-action-wins logic
      in `policy/risk.py`, not by this schema).
    - `reason`: optional human-readable explanation surfaced in the
      resulting `Decision.reasons` when this rule fires.
    """

    id: str | None = None
    match: dict[str, Any] = Field(default_factory=dict)
    action: DecisionAction
    reason: str | None = None


# Default mapping from normalized chat-message `role` strings to the
# `ProvenanceLabel` the input guard uses for risk scoring -- e.g. content
# attributed to `"user"` is treated as less trusted than `"system"`. Used
# as the `default_factory` for `Config.provenance_mapping` below; copied
# (`dict(...)`) rather than referenced directly so each `Config` instance
# gets its own independent dict that callers can safely mutate.
DEFAULT_PROVENANCE_MAPPING: dict[str, ProvenanceLabel] = {
    "user": ProvenanceLabel.USER,
    "system": ProvenanceLabel.SYSTEM,
    "assistant": ProvenanceLabel.ASSISTANT,
    "tool": ProvenanceLabel.TOOL_OUTPUT,
}


class Config(BaseModel):
    """Root model for `agentvanguard.yaml`.

    Every field below has a default (either a scalar/`Literal` default or a
    `default_factory` constructing an empty/default sub-model), which is
    what makes `Config()` -- with no YAML file at all -- a valid
    construction. See each section's class docstring above for what its
    fields mean; this class itself only adds the two cross-cutting methods
    below (`tool_manifests`, `validate_references`).
    """

    firewall: FirewallSection = Field(default_factory=FirewallSection)
    audit: AuditSection = Field(default_factory=AuditSection)
    runtime_limits: RuntimeLimits = Field(default_factory=RuntimeLimits)
    prompt_injection: PromptInjectionSection = Field(default_factory=PromptInjectionSection)
    dlp: DLPSection = Field(default_factory=DLPSection)
    provenance_mapping: dict[str, ProvenanceLabel] = Field(
        default_factory=lambda: dict(DEFAULT_PROVENANCE_MAPPING)
    )
    tool_guard: ToolGuardSection = Field(default_factory=ToolGuardSection)
    session_store: SessionStoreSection = Field(default_factory=SessionStoreSection)
    tools: dict[str, ToolConfig] = Field(default_factory=dict)
    workflows: dict[str, WorkflowConfig] = Field(default_factory=dict)
    rules: list[RuleConfig] = Field(default_factory=list)

    def tool_manifests(self) -> dict[str, ToolManifest]:
        """Build `ToolManifest`s from the `tools:` section, keyed by name."""

        # Delegates the actual conversion to `ToolConfig.to_manifest`,
        # supplying each dict key as the manifest's `name` -- this is what
        # `Engine.__init__` calls to populate `Engine.tool_manifests`.
        return {name: cfg.to_manifest(name) for name, cfg in self.tools.items()}

    def validate_references(self) -> list[str]:
        """Cross-check references between sections. Returns a list of
        human-readable error strings (empty if the config is consistent)."""

        # The only cross-section reference currently checked: every tool
        # name listed in a workflow's `allowed_tools` must correspond to an
        # actual entry under the top-level `tools:` mapping. This can't be
        # enforced by pydantic field validation alone since it requires
        # comparing two different sections of the same model instance, so
        # it's run as an explicit post-validation step by `config/loader.py`
        # (and by `cli/main.py`'s `quickstart`/`validate-config` commands)
        # after `Config.model_validate()` already succeeded.
        errors: list[str] = []
        for workflow_name, workflow in self.workflows.items():
            for tool_name in workflow.allowed_tools:
                if tool_name not in self.tools:
                    errors.append(
                        f"workflows.{workflow_name}.allowed_tools references "
                        f"unknown tool '{tool_name}' (not defined under tools:)"
                    )
        return errors
