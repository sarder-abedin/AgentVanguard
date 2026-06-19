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
    """Structural protocol (not a base class) for approval providers.

    Any object exposing a `request_approval(decision, context) -> bool`
    method satisfies this protocol — implementations do not need to
    subclass `ApprovalProvider` explicitly; `@runtime_checkable` lets
    `isinstance()` checks work against duck-typed implementations too.
    `Engine.authorize()` holds one configured instance (built by
    `approval.build_approval_provider`) and calls it exactly once per
    `REQUIRE_USER_CONFIRMATION` decision.
    """

    def request_approval(self, decision: Decision, context: PolicyInput) -> bool:
        """Return True if the action described by `context`/`decision` is
        approved by a human (or other out-of-band authority).

        `decision` is the aggregated `Decision` that triggered the approval
        request (carries `risk_score`, `reasons`, etc. for display/logging);
        `context` is the original `PolicyInput` being authorized (carries
        `tool`, `arguments`, `actor`, etc. for display/logging or for
        making an out-of-band approval decision, e.g. paging an on-call
        approver). Implementations are free to block synchronously (as
        `CLIApprovalProvider` does) or to consult an external system.
        """
        ...
