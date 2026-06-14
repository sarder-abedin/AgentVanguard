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
import urllib.request

from agent_firewall.audit.events import AuditEvent


class HttpBatchAuditSink:
    def __init__(
        self,
        endpoint: str,
        *,
        batch_size: int = 50,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.endpoint = endpoint
        self.batch_size = max(1, batch_size)
        self.headers = headers or {}
        self.timeout = timeout
        self._buffer: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self._buffer.append(event)
        if len(self._buffer) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._buffer:
            return

        payload = json.dumps([json.loads(event.model_dump_json()) for event in self._buffer]).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=payload,
            headers={"Content-Type": "application/json", **self.headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout):  # noqa: S310
                pass
        except (OSError, ValueError):
            pass
        finally:
            self._buffer = []
