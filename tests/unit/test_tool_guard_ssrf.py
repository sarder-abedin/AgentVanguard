"""Unit tests for SSRF protection in `agentvanguard.guards.tool_guard`."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentvanguard.config.loader import load
from agentvanguard.core.enums import ActionKind, ActionType, DecisionAction, FindingType
from agentvanguard.core.models import PolicyInput, ToolManifest
from agentvanguard.detectors.registry import DetectorRegistry
from agentvanguard.guards import tool_guard

FIXTURES = Path(__file__).parent.parent / "fixtures" / "payloads"


def _load_lines(name: str) -> list[str]:
    lines = []
    for line in (FIXTURES / name).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


FETCH_URL_MANIFEST = ToolManifest(name="fetch_url", action_type=ActionType.READ)


@pytest.mark.parametrize("url", _load_lines("ssrf_urls.txt"))
def test_check_ssrf_blocks_known_targets(url: str) -> None:
    findings = tool_guard._check_ssrf("url", url, FETCH_URL_MANIFEST)

    assert findings, f"expected SSRF finding for {url!r}"
    assert all(f.type == FindingType.SSRF for f in findings)


def test_check_ssrf_allows_public_host() -> None:
    findings = tool_guard._check_ssrf("url", "https://api.example.com/v1/data", FETCH_URL_MANIFEST)

    assert findings == []


def test_extract_host_handles_bare_ipv6_literals() -> None:
    """A bare IPv6 literal has no dots, so the dot-based bare-hostname check
    in `_extract_host` must not swallow it before `_check_ssrf` can inspect
    it via `ipaddress.ip_address`."""

    assert tool_guard._extract_host("::1") == "::1"
    assert tool_guard._extract_host("fd00::1") == "fd00::1"


def test_check_ssrf_blocks_bare_ipv6_loopback_host() -> None:
    findings = tool_guard._check_ssrf("host", "::1", FETCH_URL_MANIFEST)

    assert findings, "expected SSRF finding for a bare IPv6 loopback host"
    assert all(f.type == FindingType.SSRF for f in findings)


def test_check_ssrf_ignores_non_host_arguments() -> None:
    findings = tool_guard._check_ssrf("comment", "10.0.0.5 is a private IP example", FETCH_URL_MANIFEST)

    assert findings == []


def test_check_ssrf_catches_dns_rebinding(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, *args: object, **kwargs: object) -> list[tuple]:
        assert host == "rebind.example.test"
        return [(None, None, None, None, ("127.0.0.1", 0))]

    monkeypatch.setattr(tool_guard.socket, "getaddrinfo", fake_getaddrinfo)

    findings = tool_guard._check_ssrf("url", "http://rebind.example.test/", FETCH_URL_MANIFEST)

    assert findings, "expected SSRF finding for a hostname that resolves to a loopback address"
    assert all(f.type == FindingType.SSRF for f in findings)


def test_check_ssrf_dns_resolution_failure_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, *args: object, **kwargs: object) -> list[tuple]:
        raise OSError("name resolution failed")

    monkeypatch.setattr(tool_guard.socket, "getaddrinfo", fake_getaddrinfo)

    findings = tool_guard._check_ssrf("url", "http://nonexistent.example.test/", FETCH_URL_MANIFEST)

    assert findings == []


def test_tool_call_with_ssrf_argument_is_denied(tmp_path: Path) -> None:
    config_path = tmp_path / "agentvanguard.yaml"
    config_path.write_text(
        """
tools:
  fetch_url:
    action_type: read
    risk_tier: low
"""
    )
    config = load(str(config_path))
    detectors = DetectorRegistry.from_config(config)
    tool_manifests = config.tool_manifests()

    policy_input = PolicyInput(
        action=ActionKind.TOOL_CALL,
        tool="fetch_url",
        arguments={"url": "http://169.254.169.254/latest/meta-data/"},
    )

    verdict = tool_guard.evaluate(policy_input, config, detectors, tool_manifests)

    assert verdict.action == DecisionAction.DENY
    assert any(f.type == FindingType.SSRF for f in verdict.findings)
