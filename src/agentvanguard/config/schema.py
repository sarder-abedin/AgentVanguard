"""Pydantic schema for `agentvanguard.yaml`.

`Config` is the root model. Every section has built-in defaults so that
`Config()` (no file at all) is a valid, fail-closed configuration — this is
the fallback used by `config/loader.py` when no config file is found.
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
    fail_closed: bool = True
    default_workflow_mode: Literal["restrictive", "permissive"] = "restrictive"
    log_level: str = "INFO"
    approval_provider: Literal["auto_deny", "cli_prompt"] = "auto_deny"


class HttpBatchAuditConfig(BaseModel):
    """Optional `HttpBatchAuditSink`, used alongside (not instead of) the
    `jsonl` sink to ship audit events to a central collector."""

    enabled: bool = False
    endpoint: str = ""
    batch_size: int = 50
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: float = 10.0


class AuditSection(BaseModel):
    backend: Literal["jsonl"] = "jsonl"
    path: str = "./logs/agentvanguard_audit.jsonl"
    redact_secrets: bool = True
    http_batch: HttpBatchAuditConfig = Field(default_factory=HttpBatchAuditConfig)


class RuntimeLimits(BaseModel):
    max_steps: int = 12
    max_tool_calls: int = 8
    max_runtime_seconds: float = 60.0
    max_cost_usd: float = 5.00
    max_repeated_calls: int = 3


class PromptInjectionSection(BaseModel):
    enabled: bool = True
    deny_threshold: float = 0.85
    review_threshold: float = 0.65


class DLPSection(BaseModel):
    enabled: bool = True
    redact_emails: bool = False
    redact_secrets: bool = True
    redact_credit_cards: bool = True


class ToolGuardSection(BaseModel):
    """Global defaults for the tool-call guard."""

    workspace_root: str = "."
    egress_allowlist: list[str] = Field(default_factory=list)


class SessionStoreSection(BaseModel):
    """`SessionStore` backend. `in_memory` (default) is process-local;
    `redis` is shared across replicas (requires the `redis` extra)."""

    backend: Literal["in_memory", "redis"] = "in_memory"
    redis_url: str = "redis://localhost:6379/0"
    key_prefix: str = "agentvanguard:session:"
    ttl_seconds: int | None = 3600


class ToolConfig(BaseModel):
    """A tool entry under `tools:`. Same fields as `ToolManifest` minus
    `name`, which is taken from the YAML mapping key."""

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
        return ToolManifest(name=name, **self.model_dump())


class WorkflowConfig(BaseModel):
    risk_tier: RiskTier = RiskTier.MEDIUM
    allowed_agents: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    egress_allowlist: list[str] = Field(default_factory=list)


class RuleConfig(BaseModel):
    """An escalation-only custom rule, evaluated last by the policy
    evaluator. `match` keys are documented in `policy/matcher.py`."""

    id: str | None = None
    match: dict[str, Any] = Field(default_factory=dict)
    action: DecisionAction
    reason: str | None = None


DEFAULT_PROVENANCE_MAPPING: dict[str, ProvenanceLabel] = {
    "user": ProvenanceLabel.USER,
    "system": ProvenanceLabel.SYSTEM,
    "assistant": ProvenanceLabel.ASSISTANT,
    "tool": ProvenanceLabel.TOOL_OUTPUT,
}


class Config(BaseModel):
    """Root model for `agentvanguard.yaml`."""

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

        return {name: cfg.to_manifest(name) for name, cfg in self.tools.items()}

    def validate_references(self) -> list[str]:
        """Cross-check references between sections. Returns a list of
        human-readable error strings (empty if the config is consistent)."""

        errors: list[str] = []
        for workflow_name, workflow in self.workflows.items():
            for tool_name in workflow.allowed_tools:
                if tool_name not in self.tools:
                    errors.append(
                        f"workflows.{workflow_name}.allowed_tools references "
                        f"unknown tool '{tool_name}' (not defined under tools:)"
                    )
        return errors
