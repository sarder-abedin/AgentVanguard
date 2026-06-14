"""Unit tests for `agent_firewall.observability` (logging, metrics, tracing).

`prometheus-client` and `opentelemetry-api`/`-sdk` are installed in the dev
environment, so `metrics.available()`/`tracing.available()` are exercised in
their "active" branch here; the no-op fallback branches are covered by the
`try`/`except ImportError` guards themselves (not separately tested, since
uninstalling packages mid-suite isn't practical).
"""

from __future__ import annotations

import json
import logging

import pytest

from agent_firewall.observability import metrics, tracing
from agent_firewall.observability.logging import JsonFormatter, configure_logging


def _make_record(**extra: str) -> logging.LogRecord:
    record = logging.LogRecord(
        name="agent_firewall.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_json_formatter_basic_fields() -> None:
    formatted = JsonFormatter().format(_make_record())
    payload = json.loads(formatted)

    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "agent_firewall.test"
    assert "timestamp" in payload


def test_json_formatter_includes_trace_and_request_id() -> None:
    formatted = JsonFormatter().format(_make_record(trace_id="trace-123", request_id="req-456"))
    payload = json.loads(formatted)

    assert payload["trace_id"] == "trace-123"
    assert payload["request_id"] == "req-456"


def test_json_formatter_omits_missing_extra_fields() -> None:
    formatted = JsonFormatter().format(_make_record())
    payload = json.loads(formatted)

    assert "trace_id" not in payload
    assert "request_id" not in payload


@pytest.fixture()
def _restore_root_logger():
    root = logging.getLogger()
    handlers = list(root.handlers)
    level = root.level
    try:
        yield
    finally:
        root.handlers.clear()
        root.handlers.extend(handlers)
        root.setLevel(level)


def test_configure_logging_emits_json_lines(capsys: pytest.CaptureFixture[str], _restore_root_logger: None) -> None:
    configure_logging("DEBUG")

    logging.getLogger("agent_firewall.test").info("hello")

    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert payload["message"] == "hello"
    assert payload["level"] == "INFO"


def test_metrics_available() -> None:
    assert metrics.available() is True


def test_record_decision_appears_in_render_latest() -> None:
    metrics.record_decision("ingress", "ALLOW", 0.01)

    output = metrics.render_latest()

    assert b"agent_firewall_decisions_total" in output
    assert b'action="ingress"' in output


def test_tracing_available() -> None:
    assert tracing.available() is True


def test_span_is_a_usable_context_manager() -> None:
    with tracing.span("agent_firewall.test", action="ingress"):
        pass
