"""Heuristic PII detector: email, phone, SSN, and credit-card numbers.

Detection always runs for all four types — the `dlp.redact_*` config flags
(see `config/schema.py`) do not change *detection*, they control whether the
output guard turns a given `FindingType.PII` finding into a `Redaction`.
"""

from __future__ import annotations

import re

from agent_firewall.core.enums import FindingType, ProvenanceLabel, RiskTier
from agent_firewall.core.models import Finding

DETECTOR_NAME = "pii"

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9.+_-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)")
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class PIIDetector:
    """Heuristic, regex-based PII detector."""

    name = DETECTOR_NAME

    def detect(self, text: str, provenance: ProvenanceLabel) -> list[Finding]:
        if not text:
            return []

        findings: list[Finding] = []

        for match in _EMAIL_RE.finditer(text):
            findings.append(self._finding("email", RiskTier.LOW, "email address detected", match))

        for match in _PHONE_RE.finditer(text):
            findings.append(self._finding("phone", RiskTier.LOW, "phone number detected", match))

        for match in _SSN_RE.finditer(text):
            findings.append(self._finding("ssn", RiskTier.HIGH, "social security number detected", match))

        for match in _CREDIT_CARD_RE.finditer(text):
            digits = re.sub(r"[ -]", "", match.group())
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                findings.append(
                    self._finding("credit_card", RiskTier.HIGH, "credit card number detected", match)
                )

        return findings

    def _finding(self, kind: str, severity: RiskTier, message: str, match: re.Match[str]) -> Finding:
        return Finding(
            type=FindingType.PII,
            detector=f"{DETECTOR_NAME}:{kind}",
            severity=severity,
            message=message,
            span=(match.start(), match.end()),
        )
