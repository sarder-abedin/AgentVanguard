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
"""

from __future__ import annotations

import unicodedata

from agentvanguard.config.schema import Config
from agentvanguard.core.enums import DecisionAction, FindingType, GuardStage, ProvenanceLabel
from agentvanguard.core.models import ContentItem, Finding, PolicyInput, Verdict
from agentvanguard.detectors.registry import DetectorRegistry
from agentvanguard.policy.risk import finding_score, max_score

_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff"
_DETECTOR_NAMES = ("injection", "pii", "secrets")


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    for ch in _ZERO_WIDTH_CHARS:
        normalized = normalized.replace(ch, "")
    return normalized


def _content_items(policy_input: PolicyInput) -> list[ContentItem]:
    content = policy_input.content
    if content is None:
        return []
    if isinstance(content, str):
        return [ContentItem(text=content, provenance=ProvenanceLabel.USER)]
    return content


def evaluate(policy_input: PolicyInput, config: Config, detectors: DetectorRegistry) -> Verdict:
    """Run the input guard and return its `Verdict`."""

    findings: list[Finding] = []
    scores: list[float] = []
    injection_scores: list[float] = []

    for item in _content_items(policy_input):
        text = _normalize(item.text)
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

    action = DecisionAction.ALLOW
    reasons: list[str] = []

    if injection_risk_score >= deny_threshold:
        action = DecisionAction.DENY
        reasons.append(
            f"prompt injection risk score {injection_risk_score:.2f} "
            f">= deny threshold {deny_threshold:.2f}"
        )
    elif injection_risk_score >= review_threshold:
        action = DecisionAction.REQUIRE_USER_CONFIRMATION
        reasons.append(
            f"prompt injection risk score {injection_risk_score:.2f} "
            f">= review threshold {review_threshold:.2f}"
        )

    for finding in findings:
        reasons.append(f"{finding.detector}: {finding.message}")

    return Verdict(
        stage=GuardStage.INPUT,
        action=action,
        risk_score=risk_score,
        findings=findings,
        reasons=reasons,
    )
