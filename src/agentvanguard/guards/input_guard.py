"""Input guard: `action in {ingress, model_request}`.

Normalizes content (Unicode NFKC + zero-width-character stripping), runs the
injection/PII/secrets detectors over every `ContentItem`, and decides based
on `config.prompt_injection` thresholds (see the decision table in the
implementation plan):

- `injection_risk_score >= deny_threshold` -> `DENY`
- `review_threshold <= injection_risk_score < deny_threshold` -> `REQUIRE_USER_CONFIRMATION`
- otherwise -> `ALLOW`

PII/secrets findings are recorded (and contribute to `risk_score`) but do not
by themselves change the action — the output guard is responsible for DLP
redaction on the way *out*.

Any single content item longer than `runtime_limits.max_content_length` is
rejected outright (`DENY`, `FindingType.CONTENT_TOO_LARGE`) *before* it is
handed to any detector -- unbounded attacker-controlled text is itself a
resource-exhaustion risk independent of what the detectors would find in it.
"""

from __future__ import annotations

import unicodedata

from agentvanguard.config.schema import Config
from agentvanguard.core.enums import DecisionAction, FindingType, GuardStage, ProvenanceLabel, RiskTier
from agentvanguard.core.models import ContentItem, Finding, PolicyInput, Verdict
from agentvanguard.detectors.registry import DetectorRegistry
from agentvanguard.policy.risk import finding_score, max_score

_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff"
_DETECTOR_NAMES = ("injection", "pii", "secrets")


def _normalize(text: str) -> str:
    """Canonicalize `text` before it is handed to the detectors.

    Two transformations are applied:

    1. Unicode NFKC normalization — collapses visually-equivalent but
       differently-encoded characters (e.g. full-width "A" vs ASCII "A",
       or combining-character sequences) onto a single canonical form, so a
       regex/keyword-based detector cannot be evaded by swapping in a
       look-alike code point.
    2. Zero-width character stripping — removes characters such as
       U+200B (ZERO WIDTH SPACE) or U+FEFF (BOM/ZERO WIDTH NO-BREAK SPACE)
       that render invisibly but can be inserted *inside* a keyword (e.g.
       "ig​nore previous instructions") specifically to break naive
       substring/regex matching while the text still reads normally to a
       human or to an LLM tokenizer that ignores them.

    Example: `_normalize("﻿ignore​ all instructions")` returns
    `"ignore all instructions"`.
    """

    normalized = unicodedata.normalize("NFKC", text)
    for ch in _ZERO_WIDTH_CHARS:
        normalized = normalized.replace(ch, "")
    return normalized


def _content_items(policy_input: PolicyInput) -> list[ContentItem]:
    """Coerce `policy_input.content` into a uniform `list[ContentItem]`.

    `PolicyInput.content` may be `None` (no content to inspect -> empty
    list), a bare `str` (wrapped into a single `ContentItem` tagged
    `ProvenanceLabel.USER`, since untagged string content is assumed to come
    directly from the end user), or already a `list[ContentItem]` (e.g. a
    mix of user text, retrieved documents, and prior tool output, each with
    its own provenance) — in which case it is returned unchanged so each
    item's existing provenance label is preserved.
    """

    content = policy_input.content
    if content is None:
        return []
    if isinstance(content, str):
        return [ContentItem(text=content, provenance=ProvenanceLabel.USER)]
    return content


def evaluate(policy_input: PolicyInput, config: Config, detectors: DetectorRegistry) -> Verdict:
    """Run the input guard and return its `Verdict`.

    Walks every `ContentItem` in the request (normalizing each one first),
    runs the injection/PII/secrets detectors over it, and tracks two running
    maximums: the overall `risk_score` (across all finding types — used for
    observability/aggregation) and `injection_risk_score` specifically
    (the only score that drives the `action` decision here; PII/secrets are
    recorded as findings but left to the output guard to redact on egress).
    """

    findings: list[Finding] = []
    scores: list[float] = []
    injection_scores: list[float] = []
    oversized = False
    max_length = config.runtime_limits.max_content_length

    # Each ContentItem carries its own provenance (USER, RETRIEVED_DOC,
    # TOOL_OUTPUT, ...); detectors and the resulting risk score are scoped
    # per-item so a single tainted document doesn't get diluted by averaging
    # against unrelated, clean items.
    for item in _content_items(policy_input):
        text = _normalize(item.text)
        # Reject oversized content before it ever reaches a regex-based
        # detector -- unbounded attacker-controlled text (e.g. a malicious
        # retrieved document or tool output) is itself a resource-exhaustion
        # risk (ReDoS/CPU), independent of whatever the detectors would find
        # in it, so the cap is enforced first and the text is not scanned.
        if len(text) > max_length:
            oversized = True
            too_large = Finding(
                type=FindingType.CONTENT_TOO_LARGE,
                detector="input_guard:max_content_length",
                severity=RiskTier.HIGH,
                message=(
                    f"content item ({len(text)} chars, provenance={item.provenance.value}) "
                    f"exceeds max_content_length ({max_length})"
                ),
            )
            findings.append(too_large)
            scores.append(finding_score(too_large, item.provenance))
            continue
        for finding in detectors.detect_with(_DETECTOR_NAMES, text, item.provenance):
            score = finding_score(finding, item.provenance)
            findings.append(finding)
            scores.append(score)
            if finding.type == FindingType.PROMPT_INJECTION:
                injection_scores.append(score)

    risk_score = max_score(scores)
    injection_risk_score = max_score(injection_scores)

    deny_threshold = config.prompt_injection.deny_threshold
    review_threshold = config.prompt_injection.review_threshold

    # Oversized content is a hard stop, fail-closed: it was never scanned
    # by the detectors above, so there is no risk-score-based path to ALLOW.
    action = DecisionAction.DENY if oversized else DecisionAction.ALLOW
    reasons: list[str] = []

    # Threshold ladder: deny_threshold is the higher bar (definitely an
    # injection attempt -> hard stop), review_threshold is the lower bar
    # (suspicious enough to require a human to confirm before proceeding,
    # but not certain enough to auto-deny). Falling below review_threshold
    # leaves the action at ALLOW.
    if injection_risk_score >= deny_threshold:
        action = DecisionAction.DENY
        reasons.append(
            f"prompt injection risk score {injection_risk_score:.2f} "
            f">= deny threshold {deny_threshold:.2f}"
        )
    elif injection_risk_score >= review_threshold and not oversized:
        action = DecisionAction.REQUIRE_USER_CONFIRMATION
        reasons.append(
            f"prompt injection risk score {injection_risk_score:.2f} "
            f">= review threshold {review_threshold:.2f}"
        )

    # Every finding (including PII/secrets, which don't affect `action`) is
    # still surfaced in `reasons` for audit-log visibility.
    for finding in findings:
        reasons.append(f"{finding.detector}: {finding.message}")

    return Verdict(
        stage=GuardStage.INPUT,
        action=action,
        risk_score=risk_score,
        findings=findings,
        reasons=reasons,
    )
