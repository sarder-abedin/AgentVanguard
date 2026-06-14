"""Shared helper for turning `Finding.span`s into a redacted string.

Used by the output guard (DLP) and the audit logger (redacting payload
snapshots before they are written to disk).
"""

from __future__ import annotations

from agent_firewall.core.models import Finding


def apply_redactions(text: str, findings: list[Finding], replacement: str = "[REDACTED]") -> str:
    """Replace every `Finding.span` in `text` with `replacement`.

    Findings without a `span` are ignored. Spans are applied
    right-to-left so earlier offsets stay valid as the string shrinks/grows.
    """

    spans = sorted((f.span for f in findings if f.span is not None), key=lambda s: s[0], reverse=True)
    for start, end in spans:
        text = text[:start] + replacement + text[end:]
    return text
