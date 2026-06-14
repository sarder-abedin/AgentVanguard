"""Approval providers, consulted on `REQUIRE_USER_CONFIRMATION` decisions."""

from __future__ import annotations

from agent_firewall.approval.auto_deny import AutoDenyApprovalProvider
from agent_firewall.approval.base import ApprovalProvider
from agent_firewall.approval.cli_prompt import CLIApprovalProvider
from agent_firewall.config.schema import Config
from agent_firewall.core.errors import ConfigError

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
