"""Build the set of active detectors from config.

v1 ships heuristic detectors only. `prompt_injection.enabled` and
`dlp.enabled` gate whether the injection detector and the
PII/secrets/exfil detectors are registered at all; guards look detectors up
by name via `get()` regardless of which stage they run in (the secrets
detector, for example, is used by both the output guard and the tool-call
guard's credential scan).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from agentvanguard.config.schema import Config
from agentvanguard.core.enums import ProvenanceLabel
from agentvanguard.core.models import Finding
from agentvanguard.detectors.base import Detector
from agentvanguard.detectors.exfil import ExfilDetector
from agentvanguard.detectors.injection import InjectionDetector
from agentvanguard.detectors.pii import PIIDetector
from agentvanguard.detectors.secrets import SecretsDetector


class DetectorRegistry:
    """Name -> `Detector` lookup, built from config."""

    def __init__(self, detectors: dict[str, Detector]) -> None:
        # Keyed by `Detector.name` (e.g. "injection", "pii", "secrets",
        # "exfil"). Constructed directly here for tests/callers that want to
        # assemble a custom set; production code should go through
        # `from_config` instead so the active set matches `Config`.
        self._detectors = detectors

    @classmethod
    def from_config(cls, config: Config) -> "DetectorRegistry":
        """Build the registry of detectors that should be active for `config`.

        Each detector class is feature-gated by a single config flag:
        - `config.prompt_injection.enabled` controls whether
          `InjectionDetector` is registered at all.
        - `config.dlp.enabled` controls whether `PIIDetector`,
          `SecretsDetector`, and `ExfilDetector` are registered (all three
          together, since they make up "DLP" as a feature area — there is
          no per-detector DLP toggle here; finer-grained behavior such as
          `dlp.redact_*` only affects what the *output guard* does with a
          PII finding, not whether detection runs).

        A disabled feature means its detector(s) are simply absent from
        `self._detectors`, so `get()` returns `None` and `detect_with()`
        silently skips them — guards do not need to branch on config flags
        themselves, they just ask the registry for the detector by name.
        """
        detectors: dict[str, Detector] = {}

        if config.prompt_injection.enabled:
            injection = InjectionDetector()
            detectors[injection.name] = injection

        if config.dlp.enabled:
            for detector in (PIIDetector(), SecretsDetector(), ExfilDetector()):
                detectors[detector.name] = detector

        return cls(detectors)

    def get(self, name: str) -> Detector | None:
        """Look up a single detector by its registry name.

        Returns `None` if `name` is not registered — either because the
        name is unknown, or because the owning feature
        (`prompt_injection.enabled`/`dlp.enabled`) is disabled in config.
        Callers (e.g. guards) should treat a `None` result as "this
        detector is not active", not as an error.
        """
        return self._detectors.get(name)

    def __iter__(self) -> Iterator[Detector]:
        # Lets callers do `for detector in registry: ...` to iterate every
        # currently-active detector without needing to know their names.
        return iter(self._detectors.values())

    def detect_all(self, text: str, provenance: ProvenanceLabel) -> list[Finding]:
        """Run every registered (i.e. enabled) detector over `text` and
        concatenate their findings.

        `provenance` is forwarded unchanged to each detector so each can
        apply its own trust-based logic (e.g. `injection.py`'s
        provenance-weighted severity escalation). Used by guards that want
        a full scan (e.g. the input/output guard checking all DLP +
        injection signals at once) rather than a specific subset.
        """

        findings: list[Finding] = []
        for detector in self._detectors.values():
            findings.extend(detector.detect(text, provenance))
        return findings

    def detect_with(
        self, names: Iterable[str], text: str, provenance: ProvenanceLabel
    ) -> list[Finding]:
        """Run only the named detectors against `text` and concatenate
        their findings.

        `names` may include names that are not registered (e.g. a detector
        disabled via config) — those are silently skipped rather than
        raising, so callers can unconditionally request a detector (e.g.
        the tool-call guard's credential scan always asks for `["secrets"]`)
        without first checking whether DLP is enabled. Used where only a
        specific detector's signal is wanted, e.g. the tool-call guard's
        credential-exfiltration scan only runs the `secrets` detector over
        tool arguments rather than the full `detect_all` sweep.
        """

        findings: list[Finding] = []
        for name in names:
            detector = self._detectors.get(name)
            if detector is not None:
                findings.extend(detector.detect(text, provenance))
        return findings
