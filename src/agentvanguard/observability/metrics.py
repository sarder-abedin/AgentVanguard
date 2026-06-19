"""Optional Prometheus metrics (`[metrics]` extra).

`Engine.authorize()` calls `record_decision()` after every decision. The
sidecar's `GET /metrics` route calls `render_latest()`. Both are no-ops (and
`render_latest()` returns an empty body) when `prometheus-client` isn't
installed.
"""

from __future__ import annotations

# This module is imported unconditionally by `engine.py`, so it must never
# raise just because the optional `prometheus-client` package (the
# `[metrics]` extra) isn't installed. The `try` block below does the real
# setup -- importing the client library and registering the two metrics
# this module exposes -- only if the package is importable. The `except
# ImportError` branch defines fallback values for everything the `try`
# block would otherwise have defined, so the rest of this module (and any
# caller) can rely on those names existing either way. `_AVAILABLE` is the
# single flag every public function below checks to decide whether to do
# real work or silently no-op.
try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

    # Counter: total decisions made, broken down by the action kind
    # (ingress/model_request/tool_call/output) and the resulting decision
    # (ALLOW/DENY/etc.) -- lets operators graph e.g. "DENY rate for
    # tool_call" over time.
    _DECISIONS_TOTAL = Counter(
        "agentvanguard_decisions_total",
        "Total number of Engine.authorize() decisions, by action and outcome.",
        ["action", "decision"],
    )
    # Histogram: latency of `Engine.authorize()` itself, broken down by
    # action -- lets operators monitor policy-evaluation overhead and catch
    # regressions (e.g. a slow detector) per action kind.
    _AUTHORIZE_DURATION = Histogram(
        "agentvanguard_authorize_duration_seconds",
        "Time spent in Engine.authorize(), by action.",
        ["action"],
    )
    _AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the metrics extra
    # `CONTENT_TYPE_LATEST` is still referenced by the sidecar's `/metrics`
    # route to set the HTTP `Content-Type` header even when metrics aren't
    # active, so we provide the same literal value `prometheus_client`
    # would have, rather than leaving the name undefined.
    CONTENT_TYPE_LATEST = "text/plain; charset=utf-8"
    _AVAILABLE = False


def available() -> bool:
    """Whether `prometheus-client` is installed and metrics are active."""

    return _AVAILABLE


def record_decision(action: str, decision: str, duration_seconds: float) -> None:
    """Record one `Engine.authorize()` decision, or do nothing if
    `prometheus-client` isn't installed."""

    # Guard every operation on the `_DECISIONS_TOTAL`/`_AUTHORIZE_DURATION`
    # objects behind `_AVAILABLE`, since those names don't exist as real
    # Prometheus objects when the import failed above.
    if not _AVAILABLE:
        return
    _DECISIONS_TOTAL.labels(action=action, decision=decision).inc()
    _AUTHORIZE_DURATION.labels(action=action).observe(duration_seconds)


def render_latest() -> bytes:
    """Render all registered metrics in Prometheus text exposition format,
    or `b""` if `prometheus-client` isn't installed."""

    # An empty body (rather than raising) lets the sidecar's `/metrics`
    # route always return HTTP 200, even when the `[metrics]` extra isn't
    # installed -- scrapers see "no metrics" instead of an error.
    if not _AVAILABLE:
        return b""
    return generate_latest()
