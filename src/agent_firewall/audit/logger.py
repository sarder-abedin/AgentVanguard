"""`AuditLogger` — builds one `AuditEvent` per `Engine.authorize()` call and
fans it out to every configured `AuditSink`.

When `audit.redact_secrets` is enabled (the default), the `PolicyInput`
payload snapshot is run through the same `secrets`/`pii` detectors as the
output guard before being written — the audit log never contains anything
the output guard would have redacted.
"""

from __future__ import annotations

from typing import Any

from agent_firewall.audit.events import AuditEvent
from agent_firewall.audit.sinks.base import AuditSink
from agent_firewall.audit.sinks.jsonl_file import JsonlFileSink
from agent_firewall.config.schema import Config
from agent_firewall.core.enums import ProvenanceLabel
from agent_firewall.core.models import Decision, PolicyInput, Verdict
from agent_firewall.detectors.redact import apply_redactions
from agent_firewall.detectors.registry import DetectorRegistry


class AuditLogger:
    def __init__(self, sinks: list[AuditSink], config: Config, detectors: DetectorRegistry) -> None:
        self.sinks = sinks
        self.config = config
        self.detectors = detectors

    @classmethod
    def from_config(cls, config: Config, detectors: DetectorRegistry) -> "AuditLogger":
        sinks: list[AuditSink] = []
        if config.audit.backend == "jsonl":
            sinks.append(JsonlFileSink(config.audit.path))
        return cls(sinks, config, detectors)

    def log(self, policy_input: PolicyInput, decision: Decision, verdicts: list[Verdict]) -> AuditEvent:
        payload = policy_input.model_dump(mode="json", exclude_none=True)
        if self.config.audit.redact_secrets:
            payload = _redact_payload(payload, self.detectors)

        event = AuditEvent(
            trace_id=decision.trace_id,
            session_id=policy_input.session_id,
            action=policy_input.action,
            decision=decision.decision,
            risk_score=decision.risk_score,
            findings=[finding for verdict in verdicts for finding in verdict.findings],
            reasons=decision.reasons,
            payload=payload,
        )
        for sink in self.sinks:
            try:
                sink.write(event)
            except OSError:
                pass
        return event


def _redact_payload(value: Any, detectors: DetectorRegistry) -> Any:
    if isinstance(value, str):
        findings = detectors.detect_with(("secrets", "pii"), value, ProvenanceLabel.ASSISTANT)
        return apply_redactions(value, findings) if findings else value
    if isinstance(value, dict):
        return {key: _redact_payload(val, detectors) for key, val in value.items()}
    if isinstance(value, list):
        return [_redact_payload(item, detectors) for item in value]
    return value
