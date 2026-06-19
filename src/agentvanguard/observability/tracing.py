"""Optional OpenTelemetry tracing hooks (`[otel]` extra).

`Engine.authorize()` wraps its work in `span("agentvanguard.authorize", ...)`.
When `opentelemetry-api`/`opentelemetry-sdk` aren't installed, `span()` is a
no-op context manager -- the engine has zero otel dependency by default.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Iterator

# `Tracer` is only needed for the type annotation below, never at runtime --
# importing it unconditionally would reintroduce the otel dependency this
# module is designed to avoid. `TYPE_CHECKING` is always `False` at runtime,
# so this import is only ever seen by static type checkers (mypy), and the
# annotation itself is quoted (`"Tracer | None"`) so Python never needs to
# resolve the name at import time either.
if TYPE_CHECKING:
    from opentelemetry.trace import Tracer

# As in `metrics.py`: this module is imported unconditionally by
# `engine.py`, so importing the optional `opentelemetry` package (the
# `[otel]` extra) must not raise if it isn't installed. The `try` block
# performs the real setup (obtaining a `Tracer` instance) when the package
# is present; the `except ImportError` branch defines the same names
# (`_TRACER`, `_AVAILABLE`) with inert fallback values otherwise, so
# `span()` below can branch on `_TRACER is None` without needing to know
# which branch ran at import time.
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

    # No tracer configured (otel not installed) -- just run the wrapped
    # code with no tracing overhead. `yield` with nothing before/after is
    # what makes this a valid, inert context manager: callers can always
    # write `with tracing.span(...):` regardless of whether otel is active.
    if _TRACER is None:
        yield
        return

    # Real otel path: open a span for the duration of the `with` block,
    # attach each keyword argument as a span attribute (e.g.
    # `action=policy_input.action.value`) for filtering/searching in a
    # trace backend, then run the wrapped code under that span.
    with _TRACER.start_as_current_span(name) as current_span:
        for key, value in attributes.items():
            current_span.set_attribute(key, value)
        yield
