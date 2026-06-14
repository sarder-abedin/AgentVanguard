"""Detector protocol shared by all heuristic detectors.

A detector inspects a single piece of text (already tagged with a
`ProvenanceLabel` by the input/output guard) and returns zero or more
`Finding`s. Detectors are pure functions of `(text, provenance)` — no shared
state, no I/O — so they can be reused by the input guard, tool-call guard
(credential scan on arguments), and output guard (DLP) alike.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_firewall.core.enums import ProvenanceLabel
from agent_firewall.core.models import Finding


@runtime_checkable
class Detector(Protocol):
    """A named, stateless text detector."""

    name: str

    def detect(self, text: str, provenance: ProvenanceLabel) -> list[Finding]:
        """Return findings for `text`, given the trust label `provenance`."""
        ...
