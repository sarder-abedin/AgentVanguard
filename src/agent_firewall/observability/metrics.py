"""Optional Prometheus metrics (`[metrics]` extra).

`Engine.authorize()` calls `record_decision()` after every decision. The
sidecar's `GET /metrics` route calls `render_latest()`. Both are no-ops (and
`render_latest()` returns an empty body) when `prometheus-client` isn't
installed.
"""

from __future__ import annotations

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

    _DECISIONS_TOTAL = Counter(
        "agent_firewall_decisions_total",
        "Total number of Engine.authorize() decisions, by action and outcome.",
        ["action", "decision"],
    )
    _AUTHORIZE_DURATION = Histogram(
        "agent_firewall_authorize_duration_seconds",
        "Time spent in Engine.authorize(), by action.",
        ["action"],
    )
    _AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the metrics extra
    CONTENT_TYPE_LATEST = "text/plain; charset=utf-8"
    _AVAILABLE = False


def available() -> bool:
    """Whether `prometheus-client` is installed and metrics are active."""

    return _AVAILABLE


def record_decision(action: str, decision: str, duration_seconds: float) -> None:
    """Record one `Engine.authorize()` decision, or do nothing if
    `prometheus-client` isn't installed."""

    if not _AVAILABLE:
        return
    _DECISIONS_TOTAL.labels(action=action, decision=decision).inc()
    _AUTHORIZE_DURATION.labels(action=action).observe(duration_seconds)


def render_latest() -> bytes:
    """Render all registered metrics in Prometheus text exposition format,
    or `b""` if `prometheus-client` isn't installed."""

    if not _AVAILABLE:
        return b""
    return generate_latest()
