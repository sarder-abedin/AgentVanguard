"""Heuristic exfiltration-pattern detector.

Flags large encoded blobs (base64/hex) and oversized query-string values —
common shapes for smuggling data out through tool arguments, URLs, or model
output that an end user would not normally produce by hand.
"""

from __future__ import annotations

import re

from agent_firewall.core.enums import FindingType, ProvenanceLabel, RiskTier
from agent_firewall.core.models import Finding

DETECTOR_NAME = "exfil"

_BASE64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{100,}={0,2}\b")
_HEX_BLOB_RE = re.compile(r"\b[0-9a-fA-F]{128,}\b")
_LONG_QUERY_VALUE_RE = re.compile(r"[?&][A-Za-z0-9_.\-]+=[^&\s]{200,}")


class ExfilDetector:
    """Heuristic detector for large encoded blobs and oversized URL params."""

    name = DETECTOR_NAME

    def detect(self, text: str, provenance: ProvenanceLabel) -> list[Finding]:
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
        return Finding(
            type=FindingType.EXFIL_PATTERN,
            detector=f"{DETECTOR_NAME}:{kind}",
            severity=RiskTier.MEDIUM,
            message=message,
            span=(match.start(), match.end()),
        )
