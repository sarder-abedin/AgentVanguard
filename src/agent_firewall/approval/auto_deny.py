"""Default approval provider: fail-closed, non-interactive."""

from __future__ import annotations

from agent_firewall.core.models import Decision, PolicyInput


class AutoDenyApprovalProvider:
    """Always denies `REQUIRE_USER_CONFIRMATION` decisions. Safe for
    unattended/production use — every confirmation requirement becomes an
    effective `DENY` unless a real `ApprovalProvider` is configured."""

    def request_approval(self, decision: Decision, context: PolicyInput) -> bool:
        return False
