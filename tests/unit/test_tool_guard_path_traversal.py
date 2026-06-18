"""Unit tests for path-traversal protection in `agentvanguard.guards.tool_guard`."""

from __future__ import annotations

from pathlib import Path

from agentvanguard.config.loader import load
from agentvanguard.config.schema import Config
from agentvanguard.core.enums import ActionKind, ActionType, DecisionAction, FindingType
from agentvanguard.core.models import PolicyInput, ToolManifest
from agentvanguard.detectors.registry import DetectorRegistry
from agentvanguard.guards import tool_guard

READ_FILE_MANIFEST = ToolManifest(name="read_file", action_type=ActionType.READ)
EXECUTE_MANIFEST = ToolManifest(name="run_command", action_type=ActionType.EXECUTE)


def _config_with_workspace_root(workspace_root: Path) -> Config:
    config = Config()
    config.tool_guard.workspace_root = str(workspace_root)
    return config


def test_check_path_traversal_blocks_relative_escape(tmp_path: Path) -> None:
    config = _config_with_workspace_root(tmp_path)

    findings = tool_guard._check_path_traversal("path", "../../etc/passwd", READ_FILE_MANIFEST, config)

    assert findings
    assert all(f.type == FindingType.PATH_TRAVERSAL for f in findings)


def test_check_path_traversal_blocks_absolute_path_outside_workspace(tmp_path: Path) -> None:
    config = _config_with_workspace_root(tmp_path)

    findings = tool_guard._check_path_traversal("path", "/etc/passwd", READ_FILE_MANIFEST, config)

    assert findings
    assert all(f.type == FindingType.PATH_TRAVERSAL for f in findings)


def test_check_path_traversal_allows_path_within_workspace(tmp_path: Path) -> None:
    config = _config_with_workspace_root(tmp_path)

    findings = tool_guard._check_path_traversal("path", "subdir/file.txt", READ_FILE_MANIFEST, config)

    assert findings == []


def test_check_path_traversal_ignores_urls(tmp_path: Path) -> None:
    config = _config_with_workspace_root(tmp_path)

    findings = tool_guard._check_path_traversal("path", "https://example.com/file.txt", READ_FILE_MANIFEST, config)

    assert findings == []


def test_check_path_traversal_blocks_file_scheme_escape(tmp_path: Path) -> None:
    """A `file://` URI is a filesystem path, not a network resource -- it
    must still be checked against the workspace root rather than being
    exempted alongside http(s) URLs (which SSRF/egress checks cover
    instead)."""

    config = _config_with_workspace_root(tmp_path)

    findings = tool_guard._check_path_traversal("path", "file:///etc/passwd", READ_FILE_MANIFEST, config)

    assert findings
    assert all(f.type == FindingType.PATH_TRAVERSAL for f in findings)


def test_check_path_traversal_allows_file_scheme_within_workspace(tmp_path: Path) -> None:
    config = _config_with_workspace_root(tmp_path)

    findings = tool_guard._check_path_traversal(
        "path", f"file://{tmp_path}/subdir/file.txt", READ_FILE_MANIFEST, config
    )

    assert findings == []


def test_check_path_traversal_ignores_non_path_argument_for_execute(tmp_path: Path) -> None:
    config = _config_with_workspace_root(tmp_path)

    # EXECUTE tools don't get blanket path checks on non-path-shaped keys.
    findings = tool_guard._check_path_traversal("command", "../../etc/passwd", EXECUTE_MANIFEST, config)

    assert findings == []


def test_check_path_traversal_checks_any_key_for_read_write_delete(tmp_path: Path) -> None:
    config = _config_with_workspace_root(tmp_path)

    findings = tool_guard._check_path_traversal("target", "../../etc/passwd", READ_FILE_MANIFEST, config)

    assert findings


def test_tool_call_with_path_traversal_argument_is_denied(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    config_path = tmp_path / "agentvanguard.yaml"
    config_path.write_text(
        f"""
tool_guard:
  workspace_root: {workspace}

tools:
  read_file:
    action_type: read
    risk_tier: low
"""
    )
    config = load(str(config_path))
    detectors = DetectorRegistry.from_config(config)
    tool_manifests = config.tool_manifests()

    policy_input = PolicyInput(
        action=ActionKind.TOOL_CALL,
        tool="read_file",
        arguments={"path": "../../etc/passwd"},
    )

    verdict = tool_guard.evaluate(policy_input, config, detectors, tool_manifests)

    assert verdict.action == DecisionAction.DENY
    assert any(f.type == FindingType.PATH_TRAVERSAL for f in verdict.findings)


def test_tool_call_with_path_within_workspace_is_allowed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    config_path = tmp_path / "agentvanguard.yaml"
    config_path.write_text(
        f"""
tool_guard:
  workspace_root: {workspace}

tools:
  read_file:
    action_type: read
    risk_tier: low
"""
    )
    config = load(str(config_path))
    detectors = DetectorRegistry.from_config(config)
    tool_manifests = config.tool_manifests()

    policy_input = PolicyInput(
        action=ActionKind.TOOL_CALL,
        tool="read_file",
        arguments={"path": "reports/summary.txt"},
    )

    verdict = tool_guard.evaluate(policy_input, config, detectors, tool_manifests)

    assert verdict.action == DecisionAction.ALLOW
