"""`ApprovalProvider` protocol.

Consulted by `Engine.authorize()` when the aggregated decision is
`REQUIRE_USER_CONFIRMATION`. Returning `True` downgrades the decision to
`ALLOW` (or `ALLOW_WITH_MODIFICATIONS` if redactions are present); returning
`False` leaves it as `REQUIRE_USER_CONFIRMATION` (which `wrap_tool`/`wrap_agent`
treat as a block, raising `VanguardBlockedError`).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agentvanguard.core.models import Decision, PolicyInput


@runtime_checkable
class ApprovalProvider(Protocol):
    def request_approval(self, decision: Decision, context: PolicyInput) -> bool:
        """Return True if the action described by `context`/`decision` is
        approved by a human (or other out-of-band authority)."""
        ...
