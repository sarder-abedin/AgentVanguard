"""Structured (one-JSON-object-per-line) logging for the `agentvanguard`
sidecar and CLI.

`configure_logging()` is called by `agentvanguard serve`; library users of
the SDK are free to configure logging however they like -- agentvanguard
never calls `logging.basicConfig()` on import.

Unlike `metrics.py`/`tracing.py`, this module has no optional third-party
dependency -- it only uses the Python standard library `logging`/`json`
modules, so there is no try/except-ImportError fallback pattern here. It is
documented in this `observability` package because it's part of the same
"telemetry" surface area, not because it shares the no-op pattern.
"""

from __future__ import annotations

import json
import logging
import sys

# Extra, non-standard `LogRecord` attributes that should be folded into the
# JSON payload *if present*. These are typically attached by callers via
# `logger.info(..., extra={"trace_id": ..., "request_id": ...})` so that
# individual log lines can be correlated with a `Decision.trace_id` or an
# inbound HTTP request. Most `LogRecord`s won't have these set, which is why
# `format()` below uses `getattr(record, field, None)` and skips `None`s.
_EXTRA_FIELDS = ("trace_id", "request_id")


class JsonFormatter(logging.Formatter):
    """Renders each `LogRecord` as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        # Base fields present on every log line: when it happened, at what
        # level, which logger emitted it, and the rendered message text
        # (`record.getMessage()` applies any `%`-style args substitution).
        payload: dict[str, object] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Opportunistically include correlation IDs if the caller attached
        # them via the `extra=` kwarg when logging; omit them otherwise so
        # the JSON payload stays minimal for ordinary log lines.
        for field in _EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        # If this record was logged from an `except` block (or via
        # `logger.exception(...)`), include the formatted traceback so
        # errors are diagnosable from the JSON log alone.
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # `json.dumps` with default settings -- one compact JSON object per
        # line, which is what makes this format easy to ingest with
        # line-oriented log shippers (and to `grep`/`jq` by hand).
        return json.dumps(payload)


def configure_logging(level: str = "INFO") -> None:
    """Configure the root logger to emit `JsonFormatter`-formatted lines to
    stdout, replacing any existing handlers."""

    # Write to stdout (not stderr) so log lines interleave naturally with
    # other stdout-based container/process log collection.
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    # Replace rather than append: if `configure_logging()` is called more
    # than once (e.g. in tests, or if `serve` is invoked twice in-process),
    # this avoids duplicate log lines from stacked handlers on the root
    # logger.
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    # `level` is a string (e.g. "INFO", "debug") from config/CLI input;
    # `.upper()` normalizes it to what `logging.setLevel` expects.
    root.setLevel(level.upper())
