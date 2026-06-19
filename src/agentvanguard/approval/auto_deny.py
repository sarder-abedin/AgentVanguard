"""Default approval provider: fail-closed, non-interactive."""

from __future__ import annotations

from agentvanguard.core.models import Decision, PolicyInput


class AutoDenyApprovalProvider:
    """Always denies `REQUIRE_USER_CONFIRMATION` decisions. Safe for
    unattended/production use — every confirmation requirement becomes an
    effective `DENY` unless a real `ApprovalProvider` is configured."""

    def request_approval(self, decision: Decision, context: PolicyInput) -> bool:
        """Unconditionally return False, ignoring both `decision` and
        `context`.

        This is the fail-closed default: with no human in the loop, the
        only safe behavior for an action that policy flagged as needing
        confirmation is to refuse it. Callers treat a `False` return the
        same way they treat an explicit `DENY` (e.g. `wrap_tool`/
        `wrap_agent` raise `VanguardBlockedError`).
        """
        return False
