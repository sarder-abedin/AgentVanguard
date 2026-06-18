"""Output guard: `action == output`.

Runs the `pii`/`secrets`/`exfil` detectors over outbound text, then:

- For finding types covered by `config.dlp.redact_*` (see `_is_redactable`),
  builds a `Redaction` and removes the matched span from
  `Verdict.findings`' contribution to the rewritten text — the action
  becomes `ALLOW_WITH_MODIFICATIONS`.
- An unredacted `SECRET` finding with `severity == CRITICAL` (i.e.
  `dlp.redact_secrets: false` and a credential was found anyway) is a hard
  stop -> `DENY`.
- `EXFIL_PATTERN` findings are reported (and contribute to `risk_score`) but
  do not change the action by themselves.

`destination` (read from `PolicyInput.arguments["destination"]`, default
`"plain"`) drives context-aware sanitization of the rewritten text:
`"html"` -> `html.escape`, `"shell"` -> `shlex.quote`, `"sql"`/`"plain"` ->
no rewriting beyond DLP redaction.

The rewritten text (if any redaction or context-aware sanitization applied)
is returned via `Verdict.redactions` + the engine sets
`Decision.redacted_content` so callers get the sanitized text back directly.
"""

from __future__ import annotations

import html
import shlex

from agentvanguard.config.schema import Config
from agentvanguard.core.enums import DecisionAction, FindingType, GuardStage, ProvenanceLabel, RiskTier
from agentvanguard.core.models import Finding, PolicyInput, Redaction, Verdict
from agentvanguard.detectors.redact import apply_redactions
from agentvanguard.detectors.registry import DetectorRegistry
from agentvanguard.policy.risk import finding_score, max_score

_DETECTOR_NAMES = ("pii", "secrets", "exfil")


def _extract_text(policy_input: PolicyInput) -> str:
    content = policy_input.content
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    return "\n".join(item.text for item in content)


def _is_redactable(finding: Finding, config: Config) -> bool:
    if finding.type == FindingType.SECRET:
        return config.dlp.redact_secrets
    if finding.type == FindingType.PII:
        if finding.detector.endswith(":email"):
            return config.dlp.redact_emails
        if finding.detector.endswith(":credit_card"):
            return config.dlp.redact_credit_cards
        # phone / ssn: always redacted while DLP is enabled.
        return True
    return False


def evaluate(policy_input: PolicyInput, config: Config, detectors: DetectorRegistry) -> Verdict:
    """Run the output guard and return its `Verdict`."""

    text = _extract_text(policy_input)
    destination = (policy_input.arguments or {}).get("destination", "plain")

    findings = detectors.detect_with(_DETECTOR_NAMES, text, ProvenanceLabel.ASSISTANT)
    risk_score = max_score(finding_score(f) for f in findings)

    redactable = [f for f in findings if _is_redactable(f, config)]
    redactions = [Redaction(field="content", type=f.type) for f in redactable]

    action = DecisionAction.ALLOW
    reasons = [f"{f.detector}: {f.message}" for f in findings]

    for finding in findings:
        if finding not in redactable and finding.type == FindingType.SECRET and finding.severity == RiskTier.CRITICAL:
            action = DecisionAction.DENY
            reasons.append(f"unredacted critical secret in output: {finding.message}")

    rewritten = text
    if redactable:
        rewritten = apply_redactions(rewritten, redactable)
        if action == DecisionAction.ALLOW:
            action = DecisionAction.ALLOW_WITH_MODIFICATIONS

    if destination == "html":
        rewritten = html.escape(rewritten)
    elif destination == "shell":
        rewritten = shlex.quote(rewritten)

    redacted_content = rewritten if (redactable or destination in ("html", "shell")) else None

    return Verdict(
        stage=GuardStage.OUTPUT,
        action=action,
        risk_score=risk_score,
        findings=findings,
        reasons=reasons,
        redactions=redactions,
        redacted_content=redacted_content,
    )
