"""Unit tests for `agentvanguard quickstart` (`cli/main.py`)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agentvanguard.cli.main import app
from agentvanguard.config.schema import Config

runner = CliRunner()


def test_quickstart_writes_valid_config_with_default_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "agentvanguard.yaml"

    result = runner.invoke(
        app,
        ["quickstart", "--output", str(config_path)],
        input="y\nn\nn\n0\nn\ny\n",
    )

    assert result.exit_code == 0, result.output
    assert config_path.exists()

    config = Config.model_validate(yaml.safe_load(config_path.read_text()))
    assert set(config.tools) == {"lookup_order", "send_email"}
    assert config.tools["lookup_order"].action_type.value == "read"
    assert config.tools["send_email"].action_type.value == "send_external"
    assert config.tools["send_email"].requires_approval is True
    assert config.firewall.approval_provider == "auto_deny"
    assert config.runtime_limits.max_tool_calls == 5  # conservative preset
    assert not config.validate_references()


def test_quickstart_refuses_to_overwrite_without_force(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "agentvanguard.yaml"
    config_path.write_text("tools: {}\n")

    result = runner.invoke(app, ["quickstart", "--output", str(config_path)], input="\n")

    assert result.exit_code == 1
    assert "already exists" in result.output
    assert config_path.read_text() == "tools: {}\n"


def test_quickstart_custom_tool_and_permissive_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "agentvanguard.yaml"

    # modes: sdk=y, asgi=y, sidecar=n
    # tools: count=1, name=my_tool, action_type=delete
    # approvals: use cli_prompt=y
    # limits: conservative=n (permissive/default preset)
    result = runner.invoke(
        app,
        ["quickstart", "--output", str(config_path)],
        input="y\ny\nn\n1\nmy_tool\ndelete\ny\nn\n",
    )

    assert result.exit_code == 0, result.output
    assert "ASGI middleware" in result.output
    assert "Next steps" in result.output
    next_steps = result.output.split("Next steps", 1)[1]
    assert "HTTP sidecar" not in next_steps

    config = Config.model_validate(yaml.safe_load(config_path.read_text()))
    assert set(config.tools) == {"my_tool"}
    assert config.tools["my_tool"].action_type.value == "delete"
    assert config.tools["my_tool"].requires_approval is True
    assert config.firewall.approval_provider == "cli_prompt"
    assert config.runtime_limits.max_tool_calls == 8  # default (non-conservative) preset


def test_quickstart_invalid_action_type_defaults_to_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "agentvanguard.yaml"

    result = runner.invoke(
        app,
        ["quickstart", "--output", str(config_path)],
        input="n\nn\nn\n1\nweird_tool\nnotarealtype\nn\ny\n",
    )

    assert result.exit_code == 0, result.output
    assert "Unrecognized action type" in result.output

    config = Config.model_validate(yaml.safe_load(config_path.read_text()))
    assert config.tools["weird_tool"].action_type.value == "read"
