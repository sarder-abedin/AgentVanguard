"""Shared helper for turning `Finding.span`s into a redacted string.

Used by the output guard (DLP) and the audit logger (redacting payload
snapshots before they are written to disk).
"""

from __future__ import annotations

from agentvanguard.core.models import Finding


def apply_redactions(text: str, findings: list[Finding], replacement: str = "[REDACTED]") -> str:
    """Replace every `Finding.span` in `text` with `replacement`.

    Inputs:
    - `text`: the original string the findings were detected in (e.g. a
      tool result or model output before it is returned to the caller).
    - `findings`: `Finding` objects produced by one or more detectors;
      each `Finding.span`, if present, is a `(start, end)` character offset
      pair into `text` (as produced by `re.Match.start()`/`.end()`).
    - `replacement`: the literal string substituted for each matched span.

    Returns the redacted string.

    Findings without a `span` are ignored (some findings, e.g. config/
    schema-violation findings from other guards, do not refer to a specific
    substring of `text` and have nothing to redact).

    Spans are sorted by start offset and applied **right-to-left** (highest
    offset first): once a span near the end of the string is replaced,
    inserting `replacement` does not shift the character offsets of any
    span that still needs to be applied further to the left. Applying
    left-to-right instead would invalidate every subsequent span's
    `start`/`end` whenever `len(replacement) != end - start`.
    """

    spans = sorted((f.span for f in findings if f.span is not None), key=lambda s: s[0], reverse=True)
    for start, end in spans:
        text = text[:start] + replacement + text[end:]
    return text
