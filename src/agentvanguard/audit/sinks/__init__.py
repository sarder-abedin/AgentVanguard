"""Audit sinks: pluggable destinations for `AuditEvent`s.

Every sink implements the `AuditSink` protocol (`base.py`): a single
`write(event)` method. `AuditLogger.from_config` wires up zero or more sinks
based on `config.audit`, and `AuditLogger.log` writes each event to all of
them (fan-out, not a choice of one). Built-in implementations:

- `jsonl_file.JsonlFileSink` -- append-only local JSON Lines file (default).
- `http_batch.HttpBatchAuditSink` -- batches events and POSTs them to a
  central collector.
"""
