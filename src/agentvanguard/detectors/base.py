"""Detector protocol shared by all heuristic detectors.

A detector inspects a single piece of text (already tagged with a
`ProvenanceLabel` by the input/output guard) and returns zero or more
`Finding`s. Detectors are pure functions of `(text, provenance)` — no shared
state, no I/O — so they can be reused by the input guard, tool-call guard
(credential scan on arguments), and output guard (DLP) alike.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agentvanguard.core.enums import ProvenanceLabel
from agentvanguard.core.models import Finding


@runtime_checkable
class Detector(Protocol):
    """A named, stateless text detector.

    Any class that defines a `name: str` attribute and a matching
    `detect(text, provenance) -> list[Finding]` method satisfies this
    `Protocol` structurally — there is no need to subclass `Detector`
    explicitly (it is decorated `@runtime_checkable` so `isinstance(obj,
    Detector)` also works at runtime if a caller needs to check). This is
    how `registry.py` can hold `InjectionDetector`, `PIIDetector`,
    `SecretsDetector`, and `ExfilDetector` instances in one
    `dict[str, Detector]` without a common base class.
    """

    # The detector's registry key, e.g. "injection", "pii", "secrets",
    # "exfil" (see each module's `DETECTOR_NAME` constant). Guards look
    # detectors up by this name via `DetectorRegistry.get()`/`detect_with()`.
    name: str

    def detect(self, text: str, provenance: ProvenanceLabel) -> list[Finding]:
        """Return findings for `text`, given the trust label `provenance`.

        Implementations must be pure and stateless: same `(text,
        provenance)` in, same `list[Finding]` out, with no mutation of
        shared state and no I/O. `provenance` records where `text` came
        from (e.g. `USER`, `RETRIEVED_DOC`, `TOOL_OUTPUT`) so a detector can
        weight severity by trust level (see `injection.py`'s
        provenance-weighted scoring) even though the matching logic itself
        is provenance-agnostic. An empty list means "no findings", not "not
        applicable" — every detector is expected to handle any provenance.
        """
        ...
