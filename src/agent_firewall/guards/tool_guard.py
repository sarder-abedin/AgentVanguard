"""Tool-call guard: `action == tool_call`.

Checks run in order, short-circuiting on the first hard stop:

1. **Tool lookup** — calls to an unregistered tool are `DENY`'d
   (`UNKNOWN_TOOL`) — this is the core fail-closed guarantee.
2. **Caller check** — `ToolManifest.allowed_callers` (`CALLER_NOT_ALLOWED`).
3. **Workflow scoping** — `config.workflows[*].allowed_tools/allowed_agents`;
   an unregistered `workflow` falls back to
   `config.firewall.default_workflow_mode` (restrictive by default).
4. **Schema validation** — `jsonschema` against `ToolManifest.input_schema`
   (`SCHEMA_VIOLATION`).
5. For every string argument:
   - **SSRF** (`SSRF`) — resolve URL/host-like values and reject
     private/loopback/link-local/reserved ranges (covers cloud metadata
     endpoints and DNS rebinding).
   - **Path traversal** (`PATH_TRAVERSAL`) — normalize path-like values
     against `tool_guard.workspace_root`.
   - **Command injection** (`COMMAND_INJECTION`) — reject shell
     metacharacters for `action_type == EXECUTE` tools.
   - **Egress allow-list** (`EGRESS_DENIED`) — for tools with
     `side_effect == EXTERNAL_COMMUNICATION`, check resolved hosts against
     the workflow's (or global) `egress_allowlist`.
   - **Credential scan** (`SECRET`) — run the `secrets` detector over the
     argument value.
6. **Risk-tier decision** — `requires_approval` always escalates to
   `REQUIRE_USER_CONFIRMATION`; `risk_tier in {HIGH, CRITICAL}` escalates to
   `REQUIRE_USER_CONFIRMATION` if `PolicyInput.content` carries any
   `RETRIEVED_DOC`/`TOOL_OUTPUT`/`SUB_AGENT` provenance (the call was
   triggered by untrusted content).

Any finding from steps 1-5 is a hard stop -> `DENY`.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from urllib.parse import urlparse

import jsonschema

from agent_firewall.config.schema import Config, WorkflowConfig
from agent_firewall.core.enums import (
    ActionType,
    DecisionAction,
    FindingType,
    GuardStage,
    ProvenanceLabel,
    RiskTier,
    SideEffect,
)
from agent_firewall.core.models import Finding, PolicyInput, ToolManifest, Verdict
from agent_firewall.detectors.registry import DetectorRegistry
from agent_firewall.policy.risk import SEVERITY_BASE_SCORE, finding_score, max_score

_HARD_STOP_TYPES = {
    FindingType.UNKNOWN_TOOL,
    FindingType.CALLER_NOT_ALLOWED,
    FindingType.SCHEMA_VIOLATION,
    FindingType.SSRF,
    FindingType.PATH_TRAVERSAL,
    FindingType.COMMAND_INJECTION,
    FindingType.EGRESS_DENIED,
    FindingType.SECRET,
}

_UNTRUSTED_PROVENANCE = {
    ProvenanceLabel.RETRIEVED_DOC,
    ProvenanceLabel.TOOL_OUTPUT,
    ProvenanceLabel.SUB_AGENT,
}

_URL_KEY_RE = re.compile(r"(url|uri|host|hostname|endpoint|domain|address)", re.IGNORECASE)
_PATH_KEY_RE = re.compile(r"(path|file|dir|directory|folder)", re.IGNORECASE)
_SHELL_METACHARS = set(";|&`$()<>\\\n")
_BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal", "metadata.internal"}


def evaluate(
    policy_input: PolicyInput,
    config: Config,
    detectors: DetectorRegistry,
    tool_manifests: dict[str, ToolManifest],
) -> Verdict:
    """Run the tool-call guard and return its `Verdict`."""

    tool_name = policy_input.tool or ""
    manifest = tool_manifests.get(tool_name)

    if manifest is None:
        finding = Finding(
            type=FindingType.UNKNOWN_TOOL,
            detector="tool_guard",
            severity=RiskTier.CRITICAL,
            message=f"tool '{tool_name}' is not registered",
        )
        return _verdict(DecisionAction.DENY, [finding], [finding.message])

    agent_name = policy_input.agent.name if policy_input.agent else None

    if manifest.allowed_callers and agent_name not in manifest.allowed_callers:
        finding = Finding(
            type=FindingType.CALLER_NOT_ALLOWED,
            detector="tool_guard",
            severity=RiskTier.HIGH,
            message=f"agent '{agent_name}' is not an allowed caller of tool '{tool_name}'",
        )
        return _verdict(DecisionAction.DENY, [finding], [finding.message])

    workflow_name = policy_input.workflow
    if workflow_name is None and policy_input.agent is not None:
        workflow_name = policy_input.agent.workflow
    workflow_cfg = config.workflows.get(workflow_name) if workflow_name else None

    if workflow_name is not None and workflow_cfg is None:
        if config.firewall.default_workflow_mode == "restrictive" and manifest.risk_tier != RiskTier.LOW:
            reason = (
                f"workflow '{workflow_name}' is not configured; "
                f"restrictive mode requires confirmation for non-low-risk tools"
            )
            return _verdict(
                DecisionAction.REQUIRE_USER_CONFIRMATION,
                [],
                [reason],
                base_risk_score=SEVERITY_BASE_SCORE[manifest.risk_tier],
            )

    if workflow_cfg is not None:
        if workflow_cfg.allowed_tools and tool_name not in workflow_cfg.allowed_tools:
            finding = Finding(
                type=FindingType.CALLER_NOT_ALLOWED,
                detector="tool_guard",
                severity=RiskTier.HIGH,
                message=f"tool '{tool_name}' is not in workflow '{workflow_name}'.allowed_tools",
            )
            return _verdict(DecisionAction.DENY, [finding], [finding.message])

        if workflow_cfg.allowed_agents and agent_name not in workflow_cfg.allowed_agents:
            finding = Finding(
                type=FindingType.CALLER_NOT_ALLOWED,
                detector="tool_guard",
                severity=RiskTier.HIGH,
                message=f"agent '{agent_name}' is not in workflow '{workflow_name}'.allowed_agents",
            )
            return _verdict(DecisionAction.DENY, [finding], [finding.message])

    if manifest.input_schema is not None:
        try:
            jsonschema.validate(policy_input.arguments or {}, manifest.input_schema)
        except jsonschema.exceptions.ValidationError as exc:
            finding = Finding(
                type=FindingType.SCHEMA_VIOLATION,
                detector="tool_guard",
                severity=RiskTier.MEDIUM,
                message=f"arguments do not match input_schema: {exc.message}",
            )
            return _verdict(DecisionAction.DENY, [finding], [finding.message])

    findings: list[Finding] = []
    for key, value in (policy_input.arguments or {}).items():
        if not isinstance(value, str):
            continue
        findings.extend(_check_ssrf(key, value, manifest))
        findings.extend(_check_path_traversal(key, value, manifest, config))
        findings.extend(_check_command_injection(key, value, manifest))
        findings.extend(_check_egress(key, value, manifest, config, workflow_cfg))
        findings.extend(detectors.detect_with(["secrets"], value, ProvenanceLabel.ASSISTANT))

    if findings:
        hard_stops = [f for f in findings if f.type in _HARD_STOP_TYPES]
        if hard_stops:
            return _verdict(
                DecisionAction.DENY,
                findings,
                [f.message for f in hard_stops],
                base_risk_score=SEVERITY_BASE_SCORE[manifest.risk_tier],
            )

    if manifest.requires_approval:
        reason = f"tool '{tool_name}' requires user approval (risk_tier={manifest.risk_tier.value})"
        return _verdict(
            DecisionAction.REQUIRE_USER_CONFIRMATION,
            findings,
            [reason],
            required_approvals=[tool_name],
            base_risk_score=SEVERITY_BASE_SCORE[manifest.risk_tier],
        )

    if manifest.risk_tier in (RiskTier.HIGH, RiskTier.CRITICAL):
        triggering = _triggering_provenance(policy_input)
        if triggering & _UNTRUSTED_PROVENANCE:
            reason = (
                f"tool '{tool_name}' has risk_tier={manifest.risk_tier.value} and was "
                f"triggered by untrusted content ({sorted(p.value for p in triggering & _UNTRUSTED_PROVENANCE)})"
            )
            return _verdict(
                DecisionAction.REQUIRE_USER_CONFIRMATION,
                findings,
                [reason],
                base_risk_score=SEVERITY_BASE_SCORE[manifest.risk_tier],
            )

    return _verdict(
        DecisionAction.ALLOW,
        findings,
        [f.message for f in findings],
        base_risk_score=SEVERITY_BASE_SCORE[manifest.risk_tier],
    )


def _verdict(
    action: DecisionAction,
    findings: list[Finding],
    reasons: list[str],
    required_approvals: list[str] | None = None,
    base_risk_score: float = 0.0,
) -> Verdict:
    scores = [base_risk_score] + [finding_score(f) for f in findings]
    return Verdict(
        stage=GuardStage.TOOL_CALL,
        action=action,
        risk_score=max_score(scores),
        findings=findings,
        reasons=reasons,
        required_approvals=required_approvals or [],
    )


def _triggering_provenance(policy_input: PolicyInput) -> set[ProvenanceLabel]:
    if isinstance(policy_input.content, list):
        return {item.provenance for item in policy_input.content}
    return set()


def _looks_like_url(value: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value))


def _extract_host(value: str) -> str | None:
    if _looks_like_url(value):
        return urlparse(value).hostname
    if " " in value or "\t" in value or "\n" in value or "@" in value:
        return None
    if "." not in value and value.lower() != "localhost":
        return None
    return value.split("/")[0].split(":")[0] or None


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_host_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    return [str(info[4][0]) for info in infos]


def _check_ssrf(key: str, value: str, manifest: ToolManifest) -> list[Finding]:
    if not (_URL_KEY_RE.search(key) or _looks_like_url(value)):
        return []

    host = _extract_host(value)
    if host is None:
        return []

    if host.lower() in _BLOCKED_HOSTNAMES:
        return [
            Finding(
                type=FindingType.SSRF,
                detector="tool_guard:ssrf",
                severity=RiskTier.CRITICAL,
                message=f"argument '{key}' targets blocked host '{host}'",
            )
        ]

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if _is_blocked_ip(ip):
            return [
                Finding(
                    type=FindingType.SSRF,
                    detector="tool_guard:ssrf",
                    severity=RiskTier.CRITICAL,
                    message=f"argument '{key}' targets a non-public address: {host}",
                )
            ]
        return []

    for ip_str in _resolve_host_ips(host):
        try:
            resolved = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(resolved):
            return [
                Finding(
                    type=FindingType.SSRF,
                    detector="tool_guard:ssrf",
                    severity=RiskTier.CRITICAL,
                    message=f"argument '{key}' host '{host}' resolves to a non-public address: {ip_str}",
                )
            ]

    return []


def _check_path_traversal(key: str, value: str, manifest: ToolManifest, config: Config) -> list[Finding]:
    if not value or _looks_like_url(value):
        return []
    if not (_PATH_KEY_RE.search(key) or manifest.action_type in (ActionType.READ, ActionType.WRITE, ActionType.DELETE)):
        return []

    workspace_root = os.path.abspath(config.tool_guard.workspace_root)
    candidate = value if os.path.isabs(value) else os.path.join(workspace_root, value)
    normalized = os.path.normpath(candidate)

    if normalized != workspace_root and not normalized.startswith(workspace_root + os.sep):
        return [
            Finding(
                type=FindingType.PATH_TRAVERSAL,
                detector="tool_guard:path_traversal",
                severity=RiskTier.HIGH,
                message=f"argument '{key}' resolves outside the workspace root: {value!r}",
            )
        ]
    return []


def _check_command_injection(key: str, value: str, manifest: ToolManifest) -> list[Finding]:
    if manifest.action_type != ActionType.EXECUTE:
        return []
    found = _SHELL_METACHARS.intersection(value)
    if found:
        chars = "".join(sorted(found))
        return [
            Finding(
                type=FindingType.COMMAND_INJECTION,
                detector="tool_guard:command_injection",
                severity=RiskTier.HIGH,
                message=f"argument '{key}' contains shell metacharacters: {chars!r}",
            )
        ]
    return []


def _check_egress(
    key: str,
    value: str,
    manifest: ToolManifest,
    config: Config,
    workflow_cfg: WorkflowConfig | None,
) -> list[Finding]:
    if manifest.side_effect != SideEffect.EXTERNAL_COMMUNICATION and not _looks_like_url(value):
        return []

    host = _extract_host(value)
    if host is None:
        return []

    allowlist = (workflow_cfg.egress_allowlist if workflow_cfg else []) or config.tool_guard.egress_allowlist
    if not allowlist:
        return []

    if any(host == allowed or host.endswith("." + allowed) for allowed in allowlist):
        return []

    return [
        Finding(
            type=FindingType.EGRESS_DENIED,
            detector="tool_guard:egress",
            severity=RiskTier.HIGH,
            message=f"argument '{key}' host '{host}' is not in the egress allowlist",
        )
    ]
