"""Optional observability: structured logging, OpenTelemetry tracing
(`[otel]` extra), and Prometheus metrics (`[metrics]` extra).

Every module here degrades gracefully to a no-op when its optional
dependency isn't installed -- the core engine never requires these extras.
"""

from __future__ import annotations
