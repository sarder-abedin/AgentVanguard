"""Approval providers, consulted on `REQUIRE_USER_CONFIRMATION` decisions.

This package defines the pluggable "ask a human (or other authority)"
mechanism the engine falls back on when a `Decision` comes back as
`REQUIRE_USER_CONFIRMATION` (see `approval/base.py:ApprovalProvider` for the
exact contract). Two implementations ship in-tree:

- `auto_deny.py` (`AutoDenyApprovalProvider`) — the default, fail-closed,
  non-interactive provider: it always denies, so unattended deployments
  never silently auto-approve a confirmation requirement.
- `cli_prompt.py` (`CLIApprovalProvider`) — an interactive provider for
  local development that prints the decision and blocks on a y/N prompt.

`build_approval_provider` is the factory that picks between them (or future
custom providers) based on `firewall.approval_provider` in config.
"""

from __future__ import annotations

from agentvanguard.approval.auto_deny import AutoDenyApprovalProvider
from agentvanguard.approval.base import ApprovalProvider
from agentvanguard.approval.cli_prompt import CLIApprovalProvider
from agentvanguard.config.schema import Config
from agentvanguard.core.errors import ConfigError

__all__ = [
    "ApprovalProvider",
    "AutoDenyApprovalProvider",
    "CLIApprovalProvider",
    "build_approval_provider",
]


def build_approval_provider(config: Config) -> ApprovalProvider:
    """Construct the configured `ApprovalProvider` (`firewall.approval_provider`).

    Reads `config.firewall.approval_provider` (a string) and maps it to the
    corresponding concrete provider class: `"auto_deny"` ->
    `AutoDenyApprovalProvider`, `"cli_prompt"` -> `CLIApprovalProvider`. Any
    other value is a configuration error and raises `ConfigError` rather
    than silently falling back to a default — approval-provider selection
    has security implications (e.g. accidentally running `cli_prompt` in an
    unattended server context would hang on `input()`), so an unrecognized
    value must fail loudly at startup.
    """

    provider = config.firewall.approval_provider
    if provider == "auto_deny":
        return AutoDenyApprovalProvider()
    if provider == "cli_prompt":
        return CLIApprovalProvider()
    raise ConfigError(f"unknown firewall.approval_provider: {provider!r}")
