"""Unit tests for `agent_firewall.guards.output_guard` (DLP/output guard)."""

from __future__ import annotations

from agent_firewall.config.schema import Config
from agent_firewall.core.enums import ActionKind, DecisionAction, FindingType
from agent_firewall.core.models import PolicyInput
from agent_firewall.detectors.registry import DetectorRegistry
from agent_firewall.guards import output_guard


def _evaluate(text: str, config: Config | None = None, destination: str = "plain"):
    config = config or Config()
    detectors = DetectorRegistry.from_config(config)
    policy_input = PolicyInput(
        action=ActionKind.OUTPUT,
        content=text,
        arguments={"destination": destination},
    )
    return output_guard.evaluate(policy_input, config, detectors)


def test_ssn_is_redacted_by_default() -> None:
    verdict = _evaluate("My SSN is 123-45-6789.")

    assert verdict.action == DecisionAction.ALLOW_WITH_MODIFICATIONS
    assert any(f.type == FindingType.PII for f in verdict.findings)
    assert verdict.redacted_content is not None
    assert "123-45-6789" not in verdict.redacted_content
    assert "[REDACTED]" in verdict.redacted_content


def test_email_is_not_redacted_by_default() -> None:
    verdict = _evaluate("Contact us at billing@example.com for help.")

    assert any(f.detector == "pii:email" for f in verdict.findings)
    assert verdict.action == DecisionAction.ALLOW
    assert verdict.redacted_content is None


def test_email_is_redacted_when_enabled() -> None:
    config = Config()
    config.dlp.redact_emails = True

    verdict = _evaluate("Contact us at billing@example.com for help.", config=config)

    assert verdict.action == DecisionAction.ALLOW_WITH_MODIFICATIONS
    assert verdict.redacted_content is not None
    assert "billing@example.com" not in verdict.redacted_content


def test_credit_card_is_redacted_by_default() -> None:
    verdict = _evaluate("Card on file: 4111111111111111")

    assert verdict.action == DecisionAction.ALLOW_WITH_MODIFICATIONS
    assert verdict.redacted_content is not None
    assert "4111111111111111" not in verdict.redacted_content


def test_credit_card_is_not_redacted_when_disabled() -> None:
    config = Config()
    config.dlp.redact_credit_cards = False

    verdict = _evaluate("Card on file: 4111111111111111", config=config)

    assert any(f.detector == "pii:credit_card" for f in verdict.findings)
    assert verdict.action == DecisionAction.ALLOW
    assert verdict.redacted_content is None


def test_secret_is_redacted_by_default() -> None:
    verdict = _evaluate("Here is the key: AKIAIOSFODNN7EXAMPLE")

    assert verdict.action == DecisionAction.ALLOW_WITH_MODIFICATIONS
    assert verdict.redacted_content is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in verdict.redacted_content


def test_unredacted_critical_secret_is_denied() -> None:
    config = Config()
    config.dlp.redact_secrets = False

    verdict = _evaluate("Here is the key: AKIAIOSFODNN7EXAMPLE", config=config)

    assert verdict.action == DecisionAction.DENY
    assert any("unredacted critical secret" in reason for reason in verdict.reasons)


def test_exfil_finding_does_not_change_action() -> None:
    blob = "A" * 120
    verdict = _evaluate(f"data: {blob}")

    assert any(f.type == FindingType.EXFIL_PATTERN for f in verdict.findings)
    assert verdict.action == DecisionAction.ALLOW


def test_html_destination_escapes_content() -> None:
    verdict = _evaluate("<script>alert(1)</script>", destination="html")

    assert verdict.redacted_content == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_shell_destination_quotes_content() -> None:
    verdict = _evaluate("rm -rf /; echo done", destination="shell")

    assert verdict.redacted_content == "'rm -rf /; echo done'"


def test_plain_text_with_no_findings_is_allowed_unmodified() -> None:
    verdict = _evaluate("Thanks for reaching out, have a great day!")

    assert verdict.findings == []
    assert verdict.action == DecisionAction.ALLOW
    assert verdict.redacted_content is None
