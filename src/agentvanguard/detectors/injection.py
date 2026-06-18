"""Heuristic prompt-injection detector.

Matches a curated set of patterns commonly seen in direct and indirect
prompt-injection attacks (instruction override, system-prompt extraction,
jailbreak phrasing, exfiltration directives, etc.).

Severity is **provenance-weighted**: the same matched phrase is scored one
tier higher when it appears in content the model did not receive directly
from the end user (`RETRIEVED_DOC`, `TOOL_OUTPUT`, `SUB_AGENT`) than when it
appears in `USER`/`SYSTEM`/`ASSISTANT` content. This implements the
instruction-hierarchy principle from `docs/architecture.md` §4.1: a tool
result or retrieved document telling the agent to "ignore previous
instructions" is far more suspicious than a user typing the same words.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from agentvanguard.core.enums import FindingType, ProvenanceLabel, RiskTier
from agentvanguard.core.models import Finding

DETECTOR_NAME = "injection"

# Content carrying these provenance labels did not come directly from the
# end user, so injection-style phrasing in it is escalated by one severity
# tier (it is much more likely to be an attack, not a benign user request).
UNTRUSTED_PROVENANCE = {
    ProvenanceLabel.RETRIEVED_DOC,
    ProvenanceLabel.TOOL_OUTPUT,
    ProvenanceLabel.SUB_AGENT,
}

_ESCALATE = {
    RiskTier.LOW: RiskTier.MEDIUM,
    RiskTier.MEDIUM: RiskTier.HIGH,
    RiskTier.HIGH: RiskTier.CRITICAL,
    RiskTier.CRITICAL: RiskTier.CRITICAL,
}


@dataclass(frozen=True)
class InjectionPattern:
    name: str
    pattern: re.Pattern[str]
    severity: RiskTier
    message: str


_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        "instruction_override",
        re.compile(
            r"\b(ignore|disregard|forget)\b.{0,20}\b(previous|prior|above|earlier|all)\b"
            r".{0,20}\b(instructions?|prompts?|rules?|directives?)\b",
            re.IGNORECASE,
        ),
        RiskTier.HIGH,
        "instruction-override phrasing detected",
    ),
    InjectionPattern(
        "system_prompt_extraction",
        re.compile(
            r"\b(reveal|show|print|output|repeat|leak)\b.{0,20}\b(your|the)\b.{0,20}"
            r"\b(system prompt|initial instructions|hidden instructions|system message)\b",
            re.IGNORECASE,
        ),
        RiskTier.HIGH,
        "system-prompt extraction attempt detected",
    ),
    InjectionPattern(
        "jailbreak_dan",
        re.compile(r"\b(do anything now|\bDAN\b|jailbroken?\s+mode)\b", re.IGNORECASE),
        RiskTier.HIGH,
        "known jailbreak phrasing detected",
    ),
    InjectionPattern(
        "privileged_mode",
        re.compile(
            r"\b(enter|enable|switch to|activate)\b.{0,15}\b(developer|debug|admin|god|root)\b"
            r".{0,10}\bmode\b",
            re.IGNORECASE,
        ),
        RiskTier.HIGH,
        "request to enable a privileged/unrestricted mode",
    ),
    InjectionPattern(
        "unfiltered_persona",
        re.compile(
            r"\b(act as|pretend (you are|to be))\b.{0,60}"
            r"\b(without|with no|no longer (bound|restricted))\b.{0,30}"
            r"\b(restrictions?|filters?|guidelines?|rules?|limits?)\b",
            re.IGNORECASE,
        ),
        RiskTier.HIGH,
        "unfiltered/unrestricted persona request detected",
    ),
    InjectionPattern(
        "fake_system_directive",
        re.compile(
            r"\bthis is\b.{0,10}\b(a|an)\b.{0,10}\b(system|admin|developer)\b"
            r".{0,10}\b(override|message|directive|command)\b",
            re.IGNORECASE,
        ),
        RiskTier.MEDIUM,
        "spoofed system/admin directive detected",
    ),
    InjectionPattern(
        "embedded_new_instructions",
        re.compile(r"\bnew\s+(system\s+)?instructions?\s*:", re.IGNORECASE),
        RiskTier.MEDIUM,
        "embedded 'new instructions:' block detected",
    ),
    InjectionPattern(
        "hide_from_user",
        re.compile(
            r"\b(do not|don'?t)\b.{0,15}\b(tell|inform|notify|mention to)\b.{0,15}\buser\b",
            re.IGNORECASE,
        ),
        RiskTier.MEDIUM,
        "instruction to conceal actions from the user detected",
    ),
    InjectionPattern(
        "exfiltration_directive",
        re.compile(
            r"\b(send|post|upload|exfiltrate)\b.{0,40}\b(to|toward)\b.{0,40}"
            r"(https?://|www\.|[a-z0-9.-]+\.[a-z]{2,}/)",
            re.IGNORECASE,
        ),
        RiskTier.HIGH,
        "instruction to send data to an external destination detected",
    ),
]


class InjectionDetector:
    """Heuristic, regex-based prompt-injection detector."""

    name = DETECTOR_NAME

    def detect(self, text: str, provenance: ProvenanceLabel) -> list[Finding]:
        if not text:
            return []

        findings: list[Finding] = []
        for pattern in _PATTERNS:
            for match in pattern.pattern.finditer(text):
                severity = pattern.severity
                if provenance in UNTRUSTED_PROVENANCE:
                    severity = _ESCALATE[severity]
                findings.append(
                    Finding(
                        type=FindingType.PROMPT_INJECTION,
                        detector=f"{DETECTOR_NAME}:{pattern.name}",
                        severity=severity,
                        message=pattern.message,
                        span=(match.start(), match.end()),
                    )
                )
        return findings
