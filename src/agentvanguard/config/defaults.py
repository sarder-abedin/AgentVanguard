"""Built-in default configuration.

`get_default_config()` returns the in-memory fallback `Config` used by
`config/loader.py` when no config file is present — its job is to make sure
the engine always starts in a valid, fail-closed state. `DEFAULT_CONFIG_YAML`
is the annotated example written to disk by `agentvanguard init`.

These two are deliberately *not* required to be kept byte-for-byte
equivalent: `get_default_config()` returns `Config()`, i.e. whatever the
pydantic field defaults in `config/schema.py` happen to be, while
`DEFAULT_CONFIG_YAML` is a hand-maintained, heavily-commented YAML template
meant to teach a first-time user the shape of the file (including a
non-empty example `tools:`/`workflows:` section, which `Config()` does not
have by default). If you change a default in `schema.py`, consider whether
`DEFAULT_CONFIG_YAML` below should be updated to match, but the two are not
mechanically linked.
"""

from __future__ import annotations

from agentvanguard.config.schema import Config

# The annotated YAML template written verbatim to disk by `agentvanguard
# init` (see cli/main.py). Every section mirrors a model in `schema.py`;
# the inline `#` comments here are aimed at a human reading/editing the
# generated file, not at the values themselves (which mostly just restate
# `schema.py`'s field defaults).
DEFAULT_CONFIG_YAML = """\
# agentvanguard configuration
# https://github.com/ (see docs/architecture.md for the full reference)

firewall:
  fail_closed: true
  default_workflow_mode: restrictive   # restrictive | permissive
  log_level: INFO
  approval_provider: auto_deny         # auto_deny | cli_prompt

audit:
  backend: jsonl
  path: ./logs/agentvanguard_audit.jsonl
  redact_secrets: true

runtime_limits:
  max_steps: 12
  max_tool_calls: 8
  max_runtime_seconds: 60
  max_cost_usd: 5.00
  max_repeated_calls: 3

prompt_injection:
  enabled: true
  deny_threshold: 0.85
  review_threshold: 0.65

dlp:
  enabled: true
  redact_emails: false
  redact_secrets: true
  redact_credit_cards: true

# Maps normalized chat-message roles to provenance labels for the input guard.
provenance_mapping:
  user: user
  system: system
  assistant: assistant
  tool: tool_output

tool_guard:
  workspace_root: .
  egress_allowlist: []

# Declare every tool your agents can call. Tools not listed here are DENY'd
# (FindingType.UNKNOWN_TOOL) — this is the core fail-closed guarantee.
tools:
  send_email:
    description: Send an email to an external recipient.
    action_type: send_external
    side_effect: external_communication
    risk_tier: high
    reversible: false
    requires_approval: true
    allowed_callers: [support_agent, invoice_agent]

  query_customer_db:
    description: Run a read-only query against the customer database.
    action_type: read
    side_effect: internal_read
    risk_tier: medium
    reversible: true
    requires_approval: false
    allowed_callers: [support_agent]
    extra:
      max_rows: 100

# Optional: scope agents/tools/egress per workflow. Workflows not listed here
# run in `firewall.default_workflow_mode` (restrictive by default).
workflows:
  finance_invoice_review:
    risk_tier: high
    allowed_agents: [invoice_agent]
    allowed_tools: [query_customer_db]
    egress_allowlist: [company.com, trusted-vendor.com]

# Optional escalation-only custom rules, evaluated last. See
# policy/matcher.py for supported `match` keys.
rules: []
"""


def get_default_config() -> Config:
    """Return the built-in, dependency-free fallback configuration."""

    # `Config()` with no arguments relies entirely on the `Field(default=...)`
    # / `Field(default_factory=...)` values declared on every section in
    # `schema.py` -- e.g. `fail_closed=True`, empty `tools`/`workflows`
    # dicts, `approval_provider="auto_deny"`. Because every field has a
    # default, this is guaranteed to construct successfully and to be a
    # valid, fail-closed `Config` (no tools registered means every tool
    # call is denied as unknown) even when nothing else is configured.
    return Config()
