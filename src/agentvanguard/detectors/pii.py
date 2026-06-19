"""Heuristic PII detector: email, phone, SSN, and credit-card numbers.

Detection always runs for all four types — the `dlp.redact_*` config flags
(see `config/schema.py`) do not change *detection*, they control whether the
output guard turns a given `FindingType.PII` finding into a `Redaction`.
"""

from __future__ import annotations

import re

from agentvanguard.core.enums import FindingType, ProvenanceLabel, RiskTier
from agentvanguard.core.models import Finding

DETECTOR_NAME = "pii"

# Matches a standard `local-part@domain` email address, e.g.
#   "jane.doe+work@example.co.uk"
# The local part allows letters, digits, '.', '+', '_', '-' (a permissive
# but common superset of RFC 5322's local-part rules); the domain requires
# at least one '.' so bare hostnames like "@localhost" are not matched.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9.+_-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+\b")
# Matches a North American 10-digit phone number in common written forms,
# with an optional leading country code, e.g.:
#   "+1 415-555-0100", "(415) 555-0100", "415.555.0100", "4155550100"
# The `(?<!\d)`/`(?!\d)` lookaround pair (rather than `\b`) ensures the
# match doesn't start/end mid-digit-run, e.g. so a 13-digit number isn't
# partially matched as a 10-digit phone number plus 3 stray digits.
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)")
# Matches a US Social Security Number in canonical "###-##-####" form, e.g.
#   "123-45-6789"
# Deliberately narrow (hyphens required, no bare 9-digit form) to keep the
# false-positive rate low — a bare 9-digit number is too easily confused
# with other numeric IDs.
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
# Candidate matcher for credit-card-shaped digit runs: 13-19 digits
# (the valid range of real card numbers), optionally grouped with spaces or
# hyphens, e.g.:
#   "4111 1111 1111 1111", "4111-1111-1111-1111", "4111111111111111"
# This regex alone is deliberately loose (it will match *any* 13-19 digit
# run, including non-card numbers) because the real filter is the Luhn
# checksum applied below in `detect()` — combining a loose regex with a
# checksum validator catches real card numbers while rejecting most
# incidental long-digit-string false positives (e.g. order/tracking IDs).
_CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _luhn_valid(digits: str) -> bool:
    """Validate `digits` (a string of decimal digits, spaces/hyphens
    already stripped by the caller) against the Luhn checksum algorithm
    used by all major card networks.

    Walks the digits from least-significant to most-significant
    (`reversed(digits)`); every second digit (`i % 2 == 1`, i.e. the
    digits at odd positions counting from the right) is doubled, and if
    that doubling pushes it above 9, 9 is subtracted (equivalent to
    summing the two digits of the doubled value, e.g. 8*2=16 -> 1+6=7,
    which is the same as 16-9=7). The digits are summed and the number is
    valid iff the total is a multiple of 10.

    This is the standard filter that lets `_CREDIT_CARD_RE` stay loose
    (matching any 13-19 digit run) while still rejecting the vast majority
    of non-card numbers that happen to be the right length.
    """
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
        """Scan `text` for email, phone, SSN, and credit-card PII.

        `provenance` is accepted to satisfy the `Detector` protocol but is
        not used here: unlike `injection.py`, PII severity does not depend
        on where the text came from — an SSN is equally sensitive whether
        it appears in user input, a tool result, or model output.

        Detection always runs for all four PII types regardless of the
        `dlp.redact_*` config flags; those flags only affect what the
        *output guard* does with a given finding (redact vs. allow
        through), not whether this detector reports it. Returns `[]` for
        falsy/empty `text`.

        Findings are appended in a fixed scan order: email, then phone,
        then SSN, then credit card. The credit-card branch additionally
        strips spaces/hyphens from each regex match and Luhn-validates the
        result before emitting a finding — `_CREDIT_CARD_RE` alone matches
        any 13-19 digit run, so the Luhn check is what filters out
        non-card numbers of the same length.
        """
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
        # Shared constructor for this detector's findings: `kind` becomes
        # the suffix of `detector` (e.g. "pii:email"), `severity` carries
        # the per-kind risk tier (SSN/credit card are HIGH, email/phone are
        # LOW), and `match.start()`/`.end()` become the `Finding.span` used
        # by `redact.py` to redact exactly the matched substring.
        return Finding(
            type=FindingType.PII,
            detector=f"{DETECTOR_NAME}:{kind}",
            severity=severity,
            message=message,
            span=(match.start(), match.end()),
        )
