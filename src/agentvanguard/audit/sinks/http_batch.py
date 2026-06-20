"""`HttpBatchAuditSink` — ships `AuditEvent`s to a central HTTP collector in
batches, alongside (not instead of) the local `JsonlFileSink`.

Uses `urllib.request` (stdlib) so the core audit path has no hard dependency
on `httpx`. Events are buffered in memory and POSTed as a JSON array once
`batch_size` is reached; call `flush()` to send a partial batch (e.g. at
process shutdown). Like `JsonlFileSink`, failures are swallowed by
`AuditLogger.log` (best-effort, non-blocking) -- a failed flush drops the
buffered batch rather than growing it unboundedly.
"""

from __future__ import annotations

import json
import logging
import urllib.request

from agentvanguard.audit.events import AuditEvent

logger = logging.getLogger(__name__)


class HttpBatchAuditSink:
    """Buffers `AuditEvent`s in memory and POSTs them as a JSON array to a
    central collector once `batch_size` events have accumulated.

    Configured via `config.audit.http_batch.*` (see `AuditLogger.from_config`),
    this sink runs alongside -- not instead of -- the local `JsonlFileSink`,
    so disabling it never removes the only audit trail.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        batch_size: int = 50,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> None:
        # URL of the central audit collector that batches are POSTed to.
        self.endpoint = endpoint
        # Number of buffered events that triggers an automatic `flush()`.
        # Clamped to at least 1 so a misconfigured `batch_size=0` can't
        # result in `write()` never flushing (or flushing on every call in
        # an unintended way) -- one is the smallest meaningful batch.
        self.batch_size = max(1, batch_size)
        # Extra headers merged into every POST request (e.g. an API key or
        # tenant identifier expected by the collector); empty dict if none
        # configured.
        self.headers = headers or {}
        # Per-request timeout, in seconds, for the HTTP POST.
        self.timeout = timeout
        # In-memory queue of events not yet flushed. Lost on process
        # restart/crash -- this sink trades durability for low overhead,
        # which is why it is meant to complement rather than replace
        # `JsonlFileSink`.
        self._buffer: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        """Buffer `event` and flush automatically once `batch_size` events
        have accumulated.

        Unlike `JsonlFileSink.write`, this does not perform I/O on every
        call -- the network request is amortized across up to `batch_size`
        events to reduce request volume against the collector.
        """

        self._buffer.append(event)
        if len(self._buffer) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        """Send whatever is currently buffered as one POST request and clear
        the buffer, regardless of whether the send succeeds.

        Call this explicitly (e.g. at process shutdown) to ensure a partial
        batch below `batch_size` is not silently lost. If the buffer is
        empty this is a no-op (no request is made).
        """

        if not self._buffer:
            return

        # Serialize the whole batch as a single JSON array body. Each event
        # is dumped via its own `model_dump_json()` (rather than relying on
        # `json.dumps` to serialize `AuditEvent` objects directly) so
        # pydantic's own encoders are used for nested types, then
        # round-tripped through `json.loads` to get a plain list of dicts
        # that `json.dumps` can combine into one array payload.
        payload = json.dumps([json.loads(event.model_dump_json()) for event in self._buffer]).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=payload,
            headers={"Content-Type": "application/json", **self.headers},
            method="POST",
        )
        try:
            # `urlopen` is used purely for its side effect (the POST); the
            # response body/status are intentionally not inspected -- this
            # sink is fire-and-forget, matching `AuditSink.write`'s
            # best-effort contract.
            with urllib.request.urlopen(request, timeout=self.timeout):  # noqa: S310
                pass
        except (OSError, ValueError) as exc:
            # Network failures (`OSError`, including timeouts) and
            # malformed-response errors (`ValueError`) are both swallowed
            # here, on top of the `OSError` handling `AuditLogger.log`
            # already does around `sink.write()` -- this is belt-and-suspenders
            # since `flush()` can also be invoked directly by a caller
            # outside of `AuditLogger.log`. A `warning` is logged first so
            # the dropped batch (see `finally` below) is at least visible
            # to operators instead of vanishing silently.
            logger.warning(
                "agentvanguard audit: failed to flush %d event(s) to %s: %s",
                len(self._buffer),
                self.endpoint,
                exc,
            )
        finally:
            # The buffer is cleared unconditionally -- whether the POST
            # succeeded or failed -- so a persistently unreachable collector
            # drops the oldest batch and resumes buffering fresh events,
            # rather than growing `_buffer` without bound. This means a
            # failed flush is a deliberate, bounded data loss, not a retry.
            self._buffer = []
