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
    """One named regex rule: `pattern` is matched against text, and a hit
    produces a `Finding` carrying `severity` and `message`. `name` becomes
    the suffix of `Finding.detector` (e.g. "secrets:aws_access_key_id") so
    callers can tell which specific credential type fired."""

    name: str
    pattern: re.Pattern[str]
    severity: RiskTier
    message: str


_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        "aws_access_key_id",
        # AWS access key IDs always start with the literal "AKIA" prefix
        # followed by 16 uppercase-alphanumeric characters, e.g.:
        #   "AKIAIOSFODNN7EXAMPLE"
        # The "AKIA" prefix is an AWS-defined constant (other AWS ID types
        # use different prefixes, e.g. "ASIA" for temporary STS keys), so
        # this pattern has essentially no false-positive surface.
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        RiskTier.CRITICAL,
        "AWS access key ID detected",
    ),
    SecretPattern(
        "openai_api_key",
        # OpenAI-style secret keys start with "sk-" followed by 20+
        # alphanumeric characters, e.g.:
        #   "sk-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
        # The "sk-" prefix plus a long random suffix is distinctive enough
        # that this also matches other providers using the same
        # "sk-"-prefixed convention.
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        RiskTier.CRITICAL,
        "OpenAI-style API key detected",
    ),
    SecretPattern(
        "github_token",
        # GitHub's modern token formats all share a "gh" + one of
        # p(ersonal)/o(auth)/u(ser-to-server)/s(erver-to-server)/r(efresh)
        # + "_" prefix followed by 36+ alphanumeric characters, e.g.:
        #   "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
        # The character class `[pousr]` enumerates GitHub's documented
        # token-type letters (personal/oauth/user/server/refresh tokens).
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        RiskTier.CRITICAL,
        "GitHub access token detected",
    ),
    SecretPattern(
        "slack_token",
        # Slack tokens use a "xox" + one of b(ot)/a(pp)/p(ersonal)/
        # r(efresh)/s(esion) + "-" prefix followed by alphanumerics/hyphens,
        # e.g.:
        #   "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
        # The "xox<letter>-" prefix is a Slack-defined constant across all
        # of its token types, so this is a high-precision match.
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        RiskTier.CRITICAL,
        "Slack token detected",
    ),
    SecretPattern(
        "private_key",
        # Matches the PEM header line that precedes private-key material,
        # e.g.:
        #   "-----BEGIN RSA PRIVATE KEY-----"
        #   "-----BEGIN PRIVATE KEY-----"
        #   "-----BEGIN OPENSSH PRIVATE KEY-----"
        # PEM headers are a fixed, standardized format (RFC 7468), so
        # matching the literal header text reliably identifies embedded
        # key material without needing to parse the base64 body. The
        # optional group covers the common key-type/encryption qualifiers
        # that can appear between "BEGIN" and "PRIVATE KEY".
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
        RiskTier.CRITICAL,
        "PEM private key material detected",
    ),
    SecretPattern(
        "jwt",
        # Matches a JSON Web Token: three base64url segments (header,
        # payload, signature) separated by '.', where the header segment
        # starts with "eyJ" (the base64url encoding of `{"` — i.e. every
        # JSON object that starts with a quoted key, which is effectively
        # all real JWT headers), e.g.:
        #   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K"
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        RiskTier.HIGH,
        "JSON Web Token detected",
    ),
    SecretPattern(
        "generic_api_key",
        # Catch-all for the common "key_name: value" / "key_name=value"
        # assignment shape used by providers without a distinctive token
        # prefix, e.g.:
        #   "api_key: 'AbCdEfGhIjKlMnOpQrStUvWx12345678'"
        #   "SECRET_KEY=AbCdEfGhIjKlMnOpQrStUvWx12345678"
        # Matches one of several key-name aliases (api_key/apikey/
        # secret_key/access_token, case-insensitive, '_'/'-' optional)
        # followed by ':' or '=' and a 16+ character value (optionally
        # quoted). This is intentionally the lowest-precision pattern in
        # this module — it is a heuristic safety net for keys that don't
        # match a provider-specific prefix — hence its severity is HIGH
        # rather than CRITICAL like the provider-specific patterns above.
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
        """Scan `text` against every pattern in `_PATTERNS` and return one
        `Finding` per match.

        `provenance` is accepted to satisfy the `Detector` protocol but is
        not used here: a leaked credential is equally critical regardless
        of whether it appears in user input, a tool argument, or model
        output, so severity is not provenance-weighted (contrast with
        `injection.py`).

        Patterns are tried in the order they appear in `_PATTERNS`
        (provider-specific patterns first, the generic catch-all last),
        and `finditer` means a pattern can produce multiple findings if
        the same credential type appears more than once in `text`. The
        `Finding.span` on each result is the matched credential's exact
        character range, which lets the output guard (DLP) and tool-call
        guard (credential-exfiltration scan) both redact precisely the
        secret substring via `redact.py` rather than the whole text.
        Returns `[]` for falsy/empty `text`.
        """
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
