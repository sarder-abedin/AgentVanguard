"""`AuditEvent` — one record per `Engine.authorize()` call."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from agent_firewall.core.enums import ActionKind, DecisionAction
from agent_firewall.core.models import Finding


class AuditEventType(str, Enum):
    AUTHORIZATION = "authorization"


class AuditEvent(BaseModel):
    """A single audited decision, written by `AuditLogger` to every
    configured `AuditSink`."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: AuditEventType = AuditEventType.AUTHORIZATION
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trace_id: str
    session_id: str | None = None
    action: ActionKind
    decision: DecisionAction
    risk_score: float = 0.0
    findings: list[Finding] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)
