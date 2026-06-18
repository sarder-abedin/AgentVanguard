"""Heuristic secrets detector: cloud credentials, API keys, JWTs, and PEM
private key material.

Shared by the output guard (DLP — secrets leaking back to the model/user)
and the tool-call guard (credential-exfiltration scan — secrets being passed
*out* as tool arguments).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from agentvanguard.core.enums import FindingType, ProvenanceLabel, RiskTier
from agentvanguard.core.models import Finding

DETECTOR_NAME = "secrets"


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: re.Pattern[str]
    severity: RiskTier
    message: str


_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        "aws_access_key_id",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        RiskTier.CRITICAL,
        "AWS access key ID detected",
    ),
    SecretPattern(
        "openai_api_key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        RiskTier.CRITICAL,
        "OpenAI-style API key detected",
    ),
    SecretPattern(
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        RiskTier.CRITICAL,
        "GitHub access token detected",
    ),
    SecretPattern(
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        RiskTier.CRITICAL,
        "Slack token detected",
    ),
    SecretPattern(
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
        RiskTier.CRITICAL,
        "PEM private key material detected",
    ),
    SecretPattern(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        RiskTier.HIGH,
        "JSON Web Token detected",
    ),
    SecretPattern(
        "generic_api_key",
        re.compile(
            r"\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*"
            r"['\"]?[A-Za-z0-9_\-/+]{16,}['\"]?",
            re.IGNORECASE,
        ),
        RiskTier.HIGH,
        "generic API key/secret assignment detected",
    ),
]


class SecretsDetector:
    """Heuristic, regex-based secrets detector."""

    name = DETECTOR_NAME

    def detect(self, text: str, provenance: ProvenanceLabel) -> list[Finding]:
        if not text:
            return []

        findings: list[Finding] = []
        for pattern in _PATTERNS:
            for match in pattern.pattern.finditer(text):
                findings.append(
                    Finding(
                        type=FindingType.SECRET,
                        detector=f"{DETECTOR_NAME}:{pattern.name}",
                        severity=pattern.severity,
                        message=pattern.message,
                        span=(match.start(), match.end()),
                    )
                )
        return findings
