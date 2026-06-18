"""Structured (one-JSON-object-per-line) logging for the `agentvanguard`
sidecar and CLI.

`configure_logging()` is called by `agentvanguard serve`; library users of
the SDK are free to configure logging however they like -- agentvanguard
never calls `logging.basicConfig()` on import.
"""

from __future__ import annotations

import json
import logging
import sys

_EXTRA_FIELDS = ("trace_id", "request_id")


class JsonFormatter(logging.Formatter):
    """Renders each `LogRecord` as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(level: str = "INFO") -> None:
    """Configure the root logger to emit `JsonFormatter`-formatted lines to
    stdout, replacing any existing handlers."""

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
