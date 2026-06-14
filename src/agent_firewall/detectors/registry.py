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

from agent_firewall.config.schema import Config
from agent_firewall.core.enums import ProvenanceLabel
from agent_firewall.core.models import Finding
from agent_firewall.detectors.base import Detector
from agent_firewall.detectors.exfil import ExfilDetector
from agent_firewall.detectors.injection import InjectionDetector
from agent_firewall.detectors.pii import PIIDetector
from agent_firewall.detectors.secrets import SecretsDetector


class DetectorRegistry:
    """Name -> `Detector` lookup, built from config."""

    def __init__(self, detectors: dict[str, Detector]) -> None:
        self._detectors = detectors

    @classmethod
    def from_config(cls, config: Config) -> "DetectorRegistry":
        detectors: dict[str, Detector] = {}

        if config.prompt_injection.enabled:
            injection = InjectionDetector()
            detectors[injection.name] = injection

        if config.dlp.enabled:
            for detector in (PIIDetector(), SecretsDetector(), ExfilDetector()):
                detectors[detector.name] = detector

        return cls(detectors)

    def get(self, name: str) -> Detector | None:
        return self._detectors.get(name)

    def __iter__(self) -> Iterator[Detector]:
        return iter(self._detectors.values())

    def detect_all(self, text: str, provenance: ProvenanceLabel) -> list[Finding]:
        """Run every registered detector over `text`."""

        findings: list[Finding] = []
        for detector in self._detectors.values():
            findings.extend(detector.detect(text, provenance))
        return findings

    def detect_with(
        self, names: Iterable[str], text: str, provenance: ProvenanceLabel
    ) -> list[Finding]:
        """Run only the named detectors (unknown names are skipped)."""

        findings: list[Finding] = []
        for name in names:
            detector = self._detectors.get(name)
            if detector is not None:
                findings.extend(detector.detect(text, provenance))
        return findings
