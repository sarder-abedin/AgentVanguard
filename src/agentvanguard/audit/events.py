"""`AuditEvent` — one record per `Engine.authorize()` call."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from agentvanguard.core.enums import ActionKind, DecisionAction
from agentvanguard.core.models import Finding


class AuditEventType(str, Enum):
    """Discriminates the kind of record an `AuditEvent` represents.

    Currently every event written by `AuditLogger` is an `AUTHORIZATION`
    record (one per `Engine.authorize()` call). The enum exists so future
    event kinds (e.g. config-reload or approval-provider events) can be
    added to the same audit stream without changing the `AuditEvent` shape
    or breaking existing consumers that switch on `event_type`.
    """

    AUTHORIZATION = "authorization"


class AuditEvent(BaseModel):
    """A single audited decision, written by `AuditLogger` to every
    configured `AuditSink`.

    This is the durable, replayable record of "what the firewall decided and
    why" for one `Engine.authorize()` call. Every field below is chosen so
    that an external auditor or SIEM can reconstruct the decision without
    needing access to the live `Engine`/`SessionStore` state.
    """

    # Server-generated identifier for this audit record, unique per event
    # (not per decision/trace) -- distinguishes this row from any other in
    # storage/search even if `trace_id` were somehow duplicated.
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    # What kind of record this is; see `AuditEventType`. Always
    # `AUTHORIZATION` today.
    event_type: AuditEventType = AuditEventType.AUTHORIZATION
    # Wall-clock time the event was created, as an ISO-8601 string in UTC.
    # Stored as `str` (rather than `datetime`) so every sink -- including
    # `JsonlFileSink`'s plain `model_dump_json()` -- serializes it identically
    # without a custom JSON encoder.
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # Correlates this audit event with the `Decision.trace_id` returned to
    # the caller, so a decision logged/observed by an integration surface can
    # be matched back to its audit record.
    trace_id: str
    # The session this decision belongs to, if any (mirrors
    # `PolicyInput.session_id`). `None` for stateless/one-off authorizations.
    session_id: str | None = None
    # Which trust boundary was being mediated: ingress, model_request,
    # tool_call, or output (mirrors `PolicyInput.action`).
    action: ActionKind
    # The final, aggregated decision (worst-action-wins across all
    # `Verdict`s, and after any approval-provider downgrade) -- mirrors
    # `Decision.decision`.
    decision: DecisionAction
    # The aggregated risk score that drove `decision`, for trend analysis
    # and tuning thresholds after the fact.
    risk_score: float = 0.0
    # Every `Finding` produced by every `Verdict` that fed into this
    # decision (e.g. which detector matched, on what span of text) -- the
    # evidence trail behind `decision`.
    findings: list[Finding] = Field(default_factory=list)
    # Human-readable explanations for `decision`, copied from
    # `Decision.reasons` (e.g. which rule or threshold triggered it).
    reasons: list[str] = Field(default_factory=list)
    # A snapshot of the `PolicyInput` that was evaluated (serialized via
    # `model_dump(mode="json", exclude_none=True)` by `AuditLogger.log`).
    # When `audit.redact_secrets` is enabled, this snapshot has already been
    # passed through `_redact_payload` so secrets/PII detected by the same
    # detectors the output guard uses are stripped before this object is
    # ever constructed -- the audit log itself never holds raw secrets.
    payload: dict[str, Any] = Field(default_factory=dict)
