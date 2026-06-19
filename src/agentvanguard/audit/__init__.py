"""Audit logging: one `AuditEvent` per `Engine.authorize()` call.

This subpackage provides the durable record of every policy decision made by
the `Engine`. It is intentionally decoupled from policy evaluation itself:
`Engine.authorize()` calls `AuditLogger.log()` purely as a side effect, after
the `Decision` has already been computed, so a misbehaving or unreachable
audit sink can never change (or block) the authorization outcome.

See `agentvanguard.audit.events` for the `AuditEvent` schema, `logger.py` for
the `AuditLogger` that builds events and fans them out, and `sinks/` for the
pluggable destinations (`jsonl_file` for local append-only logs, `http_batch`
for shipping events to a central collector).
"""
