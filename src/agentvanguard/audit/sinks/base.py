"""`AuditSink` protocol."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agentvanguard.audit.events import AuditEvent


@runtime_checkable
class AuditSink(Protocol):
    """The minimal interface every audit destination must implement.

    `AuditLogger` treats every sink identically and uniformly: it never
    inspects sink internals, only calls `write()` and catches `OSError` per
    sink (see `AuditLogger.log`). Implementations are free to write
    synchronously (`JsonlFileSink`) or buffer internally and flush in
    batches (`HttpBatchAuditSink`) -- `write()` is the only contractual
    obligation. `@runtime_checkable` lets call sites use `isinstance()`
    against this `Protocol` (e.g. for config validation) without requiring
    sinks to explicitly subclass it.
    """

    def write(self, event: AuditEvent) -> None:
        """Persist `event`.

        Implementations should treat this as best-effort: `AuditLogger.log`
        wraps each call in a `try/except OSError`, so a sink that cannot
        reach its destination (disk full, network unavailable) should raise
        `OSError` rather than block indefinitely, so the failure is swallowed
        without affecting authorization or other sinks in the fan-out.
        """
        ...
