"""Unit tests for `agentvanguard.audit.sinks.http_batch.HttpBatchAuditSink`."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

from agentvanguard.audit.events import AuditEvent
from agentvanguard.audit.sinks.http_batch import HttpBatchAuditSink
from agentvanguard.core.enums import ActionKind, DecisionAction


def _event(trace_id: str = "trace-1") -> AuditEvent:
    return AuditEvent(trace_id=trace_id, action=ActionKind.INGRESS, decision=DecisionAction.ALLOW)


class _FakeResponse:
    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def test_write_buffers_below_batch_size_without_flushing() -> None:
    sink = HttpBatchAuditSink("http://collector.example/events", batch_size=2)

    with patch("agentvanguard.audit.sinks.http_batch.urllib.request.urlopen") as urlopen:
        sink.write(_event())

    urlopen.assert_not_called()
    assert len(sink._buffer) == 1


def test_write_flushes_once_batch_size_reached() -> None:
    sink = HttpBatchAuditSink("http://collector.example/events", batch_size=2)

    with patch("agentvanguard.audit.sinks.http_batch.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen:
        sink.write(_event("trace-1"))
        sink.write(_event("trace-2"))

    urlopen.assert_called_once()
    assert sink._buffer == []

    request = urlopen.call_args[0][0]
    payload: list[dict[str, Any]] = json.loads(request.data.decode("utf-8"))
    assert [item["trace_id"] for item in payload] == ["trace-1", "trace-2"]
    assert request.headers["Content-type"] == "application/json"


def test_flush_sends_partial_batch() -> None:
    sink = HttpBatchAuditSink("http://collector.example/events", batch_size=10)
    sink.write(_event())

    with patch("agentvanguard.audit.sinks.http_batch.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen:
        sink.flush()

    urlopen.assert_called_once()
    assert sink._buffer == []


def test_flush_empty_buffer_is_a_noop() -> None:
    sink = HttpBatchAuditSink("http://collector.example/events")

    with patch("agentvanguard.audit.sinks.http_batch.urllib.request.urlopen") as urlopen:
        sink.flush()

    urlopen.assert_not_called()


def test_flush_swallows_network_errors() -> None:
    sink = HttpBatchAuditSink("http://collector.example/events", batch_size=1)

    with patch("agentvanguard.audit.sinks.http_batch.urllib.request.urlopen", side_effect=OSError("boom")):
        sink.write(_event())

    assert sink._buffer == []


def test_request_object_carries_custom_headers() -> None:
    sink = HttpBatchAuditSink("http://collector.example/events", batch_size=1, headers={"Authorization": "Bearer xyz"})

    captured: dict[str, Any] = {}

    def _urlopen(request: Any, timeout: float) -> _FakeResponse:
        captured["request"] = request
        return _FakeResponse()

    with patch("agentvanguard.audit.sinks.http_batch.urllib.request.urlopen", side_effect=_urlopen):
        sink.write(_event())

    assert captured["request"].headers["Authorization"] == "Bearer xyz"
