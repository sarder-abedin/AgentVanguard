"""`AuditLogger` — builds one `AuditEvent` per `Engine.authorize()` call and
fans it out to every configured `AuditSink`.

When `audit.redact_secrets` is enabled (the default), the `PolicyInput`
payload snapshot is run through the same `secrets`/`pii` detectors as the
output guard before being written — the audit log never contains anything
the output guard would have redacted.
"""

from __future__ import annotations

from typing import Any

from agentvanguard.audit.events import AuditEvent
from agentvanguard.audit.sinks.base import AuditSink
from agentvanguard.audit.sinks.http_batch import HttpBatchAuditSink
from agentvanguard.audit.sinks.jsonl_file import JsonlFileSink
from agentvanguard.config.schema import Config
from agentvanguard.core.enums import ProvenanceLabel
from agentvanguard.core.models import Decision, PolicyInput, Verdict
from agentvanguard.detectors.redact import apply_redactions
from agentvanguard.detectors.registry import DetectorRegistry


class AuditLogger:
    """Builds one `AuditEvent` per `Engine.authorize()` call and writes it to
    every configured `AuditSink`. Holds no policy state of its own --
    `config` and `detectors` are only used to decide whether/how to redact
    the payload snapshot before it is persisted (see `_redact_payload`)."""

    def __init__(self, sinks: list[AuditSink], config: Config, detectors: DetectorRegistry) -> None:
        # `sinks` is the fan-out list: every event is written to all of
        # them. `config`/`detectors` are retained (rather than just the
        # derived `redact_secrets` flag) so `log()` always reflects the
        # latest config the `Engine` was built with.
        self.sinks = sinks
        self.config = config
        self.detectors = detectors

    @classmethod
    def from_config(cls, config: Config, detectors: DetectorRegistry) -> "AuditLogger":
        """Construct the `sinks` list from `config.audit`.

        At most two sinks are wired up today, and they are additive, not
        exclusive: a local `JsonlFileSink` (if `audit.backend == "jsonl"`)
        and/or a remote `HttpBatchAuditSink` (if `audit.http_batch.enabled`)
        -- both can be active at once, so a deployment can keep a local audit
        trail *and* ship events to a central collector.
        """

        sinks: list[AuditSink] = []
        if config.audit.backend == "jsonl":
            sinks.append(JsonlFileSink(config.audit.path))
        if config.audit.http_batch.enabled:
            sinks.append(
                HttpBatchAuditSink(
                    config.audit.http_batch.endpoint,
                    batch_size=config.audit.http_batch.batch_size,
                    headers=config.audit.http_batch.headers,
                    timeout=config.audit.http_batch.timeout,
                )
            )
        return cls(sinks, config, detectors)

    def log(self, policy_input: PolicyInput, decision: Decision, verdicts: list[Verdict]) -> AuditEvent:
        """Build an `AuditEvent` from this `authorize()` call's inputs/outputs
        and write it to every sink.

        Called by `Engine.authorize()` once the final `Decision` has already
        been computed (including any approval-provider downgrade) -- this
        method never influences the decision, only records it.
        """

        # Snapshot the entire `PolicyInput` (actor, agent, workflow, tool,
        # arguments, content, etc.) as plain JSON-compatible data so it can
        # be embedded verbatim in `AuditEvent.payload`. `exclude_none=True`
        # keeps the snapshot compact by omitting fields the caller didn't set.
        payload = policy_input.model_dump(mode="json", exclude_none=True)
        if self.config.audit.redact_secrets:
            # Re-run the same `secrets`/`pii` detectors the output guard
            # uses over the *entire* payload snapshot (recursively, see
            # `_redact_payload`) before it is ever attached to the
            # `AuditEvent` or handed to a sink. This guarantees the audit
            # trail -- which may be written to disk or shipped to a third
            # party -- never persists anything the output guard would have
            # redacted from a live response. Without this step, a tool-call
            # payload containing e.g. a credential or PII would be captured
            # verbatim in the audit log even though `output_guard` strips it
            # from anything actually returned to the caller.
            payload = _redact_payload(payload, self.detectors)

        event = AuditEvent(
            trace_id=decision.trace_id,
            session_id=policy_input.session_id,
            action=policy_input.action,
            decision=decision.decision,
            risk_score=decision.risk_score,
            # Flatten every `Verdict`'s `findings` into one list -- the
            # event records the union of evidence across all guard stages
            # that contributed to this single aggregated decision.
            findings=[finding for verdict in verdicts for finding in verdict.findings],
            reasons=decision.reasons,
            payload=payload,
        )
        for sink in self.sinks:
            try:
                sink.write(event)
            except OSError:
                # Audit writes are best-effort and must never block or fail
                # the request: a sink outage (disk full, network error) is
                # swallowed here so authorization itself is unaffected. Other
                # sinks in the fan-out still get a chance to write the event.
                pass
        return event


def _redact_payload(value: Any, detectors: DetectorRegistry) -> Any:
    """Recursively walk an arbitrary JSON-like structure (the
    `model_dump(mode="json")` of a `PolicyInput`) and redact any string leaf
    that the `secrets`/`pii` detectors flag.

    This mirrors what the output guard does to assistant-facing text, but
    applied to the *audit* payload instead of a response: every string
    value anywhere in the nested dict/list structure (top-level `content`,
    nested tool `arguments`, etc.) is scanned independently, so a secret
    buried three levels deep in a tool-call argument is redacted just as
    reliably as a top-level `content` field.
    """

    if isinstance(value, str):
        # `ProvenanceLabel.ASSISTANT` is used here (rather than e.g. USER)
        # because the detectors' redaction behavior is keyed by provenance;
        # treating the payload as assistant-provenance text gives the same
        # redaction policy the output guard applies to outbound content.
        findings = detectors.detect_with(("secrets", "pii"), value, ProvenanceLabel.ASSISTANT)
        return apply_redactions(value, findings) if findings else value
    if isinstance(value, dict):
        return {key: _redact_payload(val, detectors) for key, val in value.items()}
    if isinstance(value, list):
        return [_redact_payload(item, detectors) for item in value]
    # Non-string, non-dict, non-list leaves (numbers, bools, None) cannot
    # carry detector matches and are returned unchanged.
    return value
