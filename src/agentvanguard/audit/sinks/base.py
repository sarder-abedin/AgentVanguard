"""`AuditSink` protocol."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agentvanguard.audit.events import AuditEvent


@runtime_checkable
class AuditSink(Protocol):
    def write(self, event: AuditEvent) -> None:
        """Persist `event`."""
        ...
