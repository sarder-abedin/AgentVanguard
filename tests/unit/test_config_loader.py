"""Unit tests for `agent_firewall.config.loader` and `config.schema`."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_firewall.config.defaults import DEFAULT_CONFIG_YAML, get_default_config
from agent_firewall.config.loader import CONFIG_ENV_VAR, load, resolve_config_path
from agent_firewall.core.enums import ActionType, RiskTier
from agent_firewall.core.errors import ConfigError


def test_get_default_config_is_valid_and_fail_closed() -> None:
    config = get_default_config()

    assert config.firewall.fail_closed is True
    assert config.firewall.default_workflow_mode == "restrictive"
    assert config.tools == {}
    assert config.workflows == {}
    assert config.validate_references() == []


def test_load_with_no_path_and_no_file_falls_back_to_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(CONFIG_ENV_VAR, raising=False)
    monkeypatch.chdir(tmp_path)

    config = load(None)

    assert config.tools == {}
    assert config.firewall.approval_provider == "auto_deny"


def test_load_explicit_path(tmp_path: Path) -> None:
    config_path = tmp_path / "agent_firewall.yaml"
    config_path.write_text(DEFAULT_CONFIG_YAML)

    config = load(str(config_path))

    assert "send_email" in config.tools
    assert "query_customer_db" in config.tools
    assert "finance_invoice_review" in config.workflows


def test_load_explicit_path_missing_file_raises_config_error(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.yaml"

    with pytest.raises(ConfigError):
        load(str(missing))


def test_load_invalid_yaml_raises_config_error(tmp_path: Path) -> None:
    config_path = tmp_path / "agent_firewall.yaml"
    config_path.write_text("firewall: [this, is, not, a, mapping]\n")

    with pytest.raises(ConfigError):
        load(str(config_path))


def test_load_validates_cross_references(tmp_path: Path) -> None:
    config_path = tmp_path / "agent_firewall.yaml"
    config_path.write_text(
        """
tools:
  query_customer_db:
    action_type: read

workflows:
  finance_invoice_review:
    allowed_tools: [unknown_tool]
"""
    )

    with pytest.raises(ConfigError):
        load(str(config_path))


def test_resolve_config_path_uses_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "custom.yaml"
    config_path.write_text(DEFAULT_CONFIG_YAML)
    monkeypatch.setenv(CONFIG_ENV_VAR, str(config_path))

    resolved = resolve_config_path(None)

    assert resolved == config_path


def test_resolve_config_path_explicit_arg_wins_over_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_path = tmp_path / "env.yaml"
    env_path.write_text(DEFAULT_CONFIG_YAML)
    arg_path = tmp_path / "arg.yaml"
    arg_path.write_text(DEFAULT_CONFIG_YAML)
    monkeypatch.setenv(CONFIG_ENV_VAR, str(env_path))

    resolved = resolve_config_path(str(arg_path))

    assert resolved == arg_path


def test_tool_manifests_built_from_config(tmp_path: Path) -> None:
    config_path = tmp_path / "agent_firewall.yaml"
    config_path.write_text(DEFAULT_CONFIG_YAML)
    config = load(str(config_path))

    manifests = config.tool_manifests()

    send_email = manifests["send_email"]
    assert send_email.action_type == ActionType.SEND_EXTERNAL
    assert send_email.risk_tier == RiskTier.HIGH
    assert send_email.requires_approval is True
    assert send_email.allowed_callers == ["support_agent", "invoice_agent"]
