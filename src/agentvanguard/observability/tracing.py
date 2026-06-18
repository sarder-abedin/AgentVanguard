"""Optional OpenTelemetry tracing hooks (`[otel]` extra).

`Engine.authorize()` wraps its work in `span("agentvanguard.authorize", ...)`.
When `opentelemetry-api`/`opentelemetry-sdk` aren't installed, `span()` is a
no-op context manager -- the engine has zero otel dependency by default.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from opentelemetry.trace import Tracer

try:
    from opentelemetry import trace

    _TRACER: "Tracer | None" = trace.get_tracer("agentvanguard")
    _AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the otel extra
    _TRACER = None
    _AVAILABLE = False


def available() -> bool:
    """Whether `opentelemetry` is installed and tracing is active."""

    return _AVAILABLE


@contextmanager
def span(name: str, **attributes: str) -> Iterator[None]:
    """Start a span named `name` with `attributes`, or do nothing if otel
    isn't installed."""

    if _TRACER is None:
        yield
        return

    with _TRACER.start_as_current_span(name) as current_span:
        for key, value in attributes.items():
            current_span.set_attribute(key, value)
        yield
