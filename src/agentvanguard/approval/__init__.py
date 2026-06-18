"""Approval providers, consulted on `REQUIRE_USER_CONFIRMATION` decisions."""

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
    """Construct the configured `ApprovalProvider` (`firewall.approval_provider`)."""

    provider = config.firewall.approval_provider
    if provider == "auto_deny":
        return AutoDenyApprovalProvider()
    if provider == "cli_prompt":
        return CLIApprovalProvider()
    raise ConfigError(f"unknown firewall.approval_provider: {provider!r}")
