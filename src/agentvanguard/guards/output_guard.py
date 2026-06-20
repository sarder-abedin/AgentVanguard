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

Output longer than `runtime_limits.max_content_length` is rejected outright
(`DENY`, `FindingType.CONTENT_TOO_LARGE`) *before* any detector runs over it
-- there is no safe redaction of text that was never scanned.
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

_MAX_LENGTH_DETECTOR = "output_guard:max_content_length"

_DETECTOR_NAMES = ("pii", "secrets", "exfil")


def _extract_text(policy_input: PolicyInput) -> str:
    """Flatten `policy_input.content` to a single string for the detectors
    to scan. `None` -> empty string (nothing to scan); a bare `str` is
    returned as-is; a `list[ContentItem]` (e.g. several output chunks) is
    joined with newlines so detectors still see one contiguous text and
    multi-line patterns spanning chunk boundaries aren't artificially
    split."""

    content = policy_input.content
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    return "\n".join(item.text for item in content)


def _is_redactable(finding: Finding, config: Config) -> bool:
    """Decide whether `finding` should be redacted from the outgoing text,
    based on the `dlp.redact_*` toggles in `config`.

    - `SECRET` findings are redacted only if `config.dlp.redact_secrets` is
      enabled; if it's disabled, the finding survives into the "not
      redactable" set, and `evaluate()` then escalates a `CRITICAL`-severity
      unredacted secret all the way to `DENY` (see the hard-stop check
      below) rather than letting it through unmodified.
    - `PII` findings differentiate by sub-type: emails and credit cards each
      have their own opt-in toggle (`redact_emails`/`redact_credit_cards`),
      while phone numbers and SSNs (anything that doesn't end in
      `:email`/`:credit_card`) are always redacted whenever DLP detectors
      are enabled at all — there is no separate toggle to leave them
      unredacted.
    - Any other finding type (e.g. `EXFIL_PATTERN`) is never redacted; it is
      reported for visibility but the text is left untouched.
    """

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
    """Run the output guard and return its `Verdict`.

    High-level flow: scan the outbound text for PII/secrets/exfiltration
    patterns, split the findings into "redactable" vs. "not redactable"
    based on the DLP config, redact the redactable ones out of the text,
    hard-stop (`DENY`) on any unredacted critical secret, and finally apply
    destination-specific escaping (HTML-escape or shell-quote) to whatever
    text survives. The caller (the engine) reads `Verdict.redacted_content`
    to decide what to actually hand back if anything was rewritten.
    """

    text = _extract_text(policy_input)
    destination = (policy_input.arguments or {}).get("destination", "plain")

    # Reject oversized output before it ever reaches a regex-based detector --
    # unbounded text is itself a resource-exhaustion risk independent of what
    # the detectors would find in it. This is a hard stop: there is no safe
    # redaction of text that was never scanned.
    max_length = config.runtime_limits.max_content_length
    if len(text) > max_length:
        too_large = Finding(
            type=FindingType.CONTENT_TOO_LARGE,
            detector=_MAX_LENGTH_DETECTOR,
            severity=RiskTier.HIGH,
            message=f"output content ({len(text)} chars) exceeds max_content_length ({max_length})",
        )
        return Verdict(
            stage=GuardStage.OUTPUT,
            action=DecisionAction.DENY,
            risk_score=finding_score(too_large),
            findings=[too_large],
            reasons=[f"{too_large.detector}: {too_large.message}"],
        )

    findings = detectors.detect_with(_DETECTOR_NAMES, text, ProvenanceLabel.ASSISTANT)
    risk_score = max_score(finding_score(f) for f in findings)

    # Split findings by whether config allows automatically scrubbing them.
    # `redactable` drives both the text rewrite below and the `Redaction`
    # records attached to the Verdict (for audit purposes); anything left
    # out of `redactable` passes through unredacted and may still trigger
    # the hard-stop check further down.
    redactable = [f for f in findings if _is_redactable(f, config)]
    redactions = [Redaction(field="content", type=f.type) for f in redactable]

    action = DecisionAction.ALLOW
    reasons = [f"{f.detector}: {f.message}" for f in findings]

    # Hard stop: a CRITICAL-severity secret that DLP config left
    # unredactable (i.e. `dlp.redact_secrets: false`) must not be allowed to
    # leave as-is — there's no safe rewrite for a live credential, so the
    # whole output is denied rather than shipped with the secret intact.
    for finding in findings:
        if finding not in redactable and finding.type == FindingType.SECRET and finding.severity == RiskTier.CRITICAL:
            action = DecisionAction.DENY
            reasons.append(f"unredacted critical secret in output: {finding.message}")

    rewritten = text
    if redactable:
        # Replace each redactable finding's matched span in the text (e.g.
        # an email address or phone number) with a redaction placeholder.
        # If nothing else has already forced a DENY, downgrade the action
        # to ALLOW_WITH_MODIFICATIONS so callers know the text changed.
        rewritten = apply_redactions(rewritten, redactable)
        if action == DecisionAction.ALLOW:
            action = DecisionAction.ALLOW_WITH_MODIFICATIONS

    # Destination-aware sanitization: rewrite the (possibly already
    # redacted) text so it's safe to drop into the target context. "html"
    # neutralizes markup/script injection via HTML entity escaping; "shell"
    # wraps the value so it's treated as a single safe shell token rather
    # than parsed for metacharacters; "sql"/"plain" destinations get no
    # extra rewriting here (DLP redaction above is the only transformation
    # applied to them).
    if destination == "html":
        rewritten = html.escape(rewritten)
    elif destination == "shell":
        rewritten = shlex.quote(rewritten)

    # Only surface `redacted_content` if the text actually differs from the
    # original for one of the two reasons above (DLP redaction or
    # destination escaping) — otherwise leave it None so callers know to
    # use the original, unmodified text.
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
