"""Optional observability: structured logging, OpenTelemetry tracing
(`[otel]` extra), and Prometheus metrics (`[metrics]` extra).

Every module here degrades gracefully to a no-op when its optional
dependency isn't installed -- the core engine never requires these extras.

Concretely, each submodule (`logging.py`, `metrics.py`, `tracing.py`) wraps
its optional third-party import in a `try`/`except ImportError` block at
module import time. If the dependency is present, the module wires up the
real implementation (Prometheus counters/histograms, an OpenTelemetry
tracer, etc.) and sets an internal `_AVAILABLE = True` flag. If the
dependency is missing, the `except` branch sets safe fallback values (e.g.
`_AVAILABLE = False`, dummy constants) so that every public function in the
module can check that flag and either do the real work or silently return
(`None`, `b""`, or a no-op context manager) instead of raising. This means
`import agentvanguard.observability...` -- and therefore `import
agentvanguard` itself, since `engine.py` imports `metrics`/`tracing`
unconditionally -- never fails just because `prometheus-client` or
`opentelemetry-api`/`sdk` aren't installed. Callers (e.g. `Engine.authorize`)
call these functions unconditionally and get correct behavior either way:
real telemetry when the extra is installed, harmless no-ops when it isn't.
"""

from __future__ import annotations
