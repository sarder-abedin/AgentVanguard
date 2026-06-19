"""Heuristic exfiltration-pattern detector.

Flags large encoded blobs (base64/hex) and oversized query-string values —
common shapes for smuggling data out through tool arguments, URLs, or model
output that an end user would not normally produce by hand.
"""

from __future__ import annotations

import re

from agentvanguard.core.enums import FindingType, ProvenanceLabel, RiskTier
from agentvanguard.core.models import Finding

DETECTOR_NAME = "exfil"

# Matches a run of 100+ base64 alphabet characters (A-Z, a-z, 0-9, '+', '/'),
# with up to two trailing '=' padding characters, e.g.:
#   "U3VwZXIgc2VjcmV0IGRhdGEgdGhhdCBzb21lb25lIGlzIHRyeWluZyB0byBzbmVhayBvdXQ...=="
# 100 characters of base64 decodes to ~75 bytes — long enough that it is very
# unlikely to be a normal word, short ID, or token a person would type by
# hand, but short blobs (UUIDs, hashes, short tokens) are common and
# benign, hence the high length threshold to avoid false positives.
_BASE64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{100,}={0,2}\b")
# Matches a run of 128+ hex digits, e.g. a long hex-encoded payload such as
#   "4a3f9c1e2b7d...." (128+ chars)
# 128 hex chars = 64 bytes; ordinary hashes (SHA-256 = 64 hex chars, SHA-512
# = 128 hex chars) sit right at or below this threshold, so this pattern is
# tuned to catch *larger* encoded blobs rather than a single routine hash.
_HEX_BLOB_RE = re.compile(r"\b[0-9a-fA-F]{128,}\b")
# Matches a URL query-string key=value pair whose value is 200+ characters,
# e.g.:
#   "https://example.com/track?data=<200+ arbitrary characters>"
# A legitimate query parameter (an ID, a token, a search term) is rarely
# this long; a 200+ character value smuggled into a query string is a
# classic shape for exfiltrating data via an otherwise-innocuous-looking
# URL (e.g. passed to a `fetch`/`curl`-style tool).
_LONG_QUERY_VALUE_RE = re.compile(r"[?&][A-Za-z0-9_.\-]+=[^&\s]{200,}")


class ExfilDetector:
    """Heuristic detector for large encoded blobs and oversized URL params."""

    name = DETECTOR_NAME

    def detect(self, text: str, provenance: ProvenanceLabel) -> list[Finding]:
        """Scan `text` for exfiltration-shaped content and return findings.

        `provenance` is accepted to satisfy the `Detector` protocol but is
        not used to vary behavior here: unlike `injection.py`, this detector
        does not weight severity by trust level — a large encoded blob is
        equally suspicious regardless of where the text came from.

        Returns one `Finding` (always `RiskTier.MEDIUM`, `FindingType.
        EXFIL_PATTERN`) per regex match, in match order: first all hex-blob
        matches, then all base64-blob matches, then all oversized
        query-value matches. Returns `[]` for falsy/empty `text`.
        """
        if not text:
            return []

        findings: list[Finding] = []

        for match in _HEX_BLOB_RE.finditer(text):
            findings.append(self._finding("hex_blob", "large hex-encoded blob detected", match))

        for match in _BASE64_BLOB_RE.finditer(text):
            findings.append(self._finding("base64_blob", "large base64-encoded blob detected", match))

        for match in _LONG_QUERY_VALUE_RE.finditer(text):
            findings.append(
                self._finding("long_query_value", "oversized URL query parameter detected", match)
            )

        return findings

    def _finding(self, kind: str, message: str, match: re.Match[str]) -> Finding:
        # Shared constructor for this detector's findings: `kind` becomes
        # the suffix of `detector` (e.g. "exfil:hex_blob") so callers can
        # tell which specific pattern fired, and `match.start()`/`.end()`
        # become the `Finding.span` used by `redact.py` to redact the blob.
        return Finding(
            type=FindingType.EXFIL_PATTERN,
            detector=f"{DETECTOR_NAME}:{kind}",
            severity=RiskTier.MEDIUM,
            message=message,
            span=(match.start(), match.end()),
        )
