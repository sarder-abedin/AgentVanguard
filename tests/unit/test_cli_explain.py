"""Unit tests for `agentvanguard explain <trace_id>` (`cli/main.py`)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agentvanguard.cli.main import app

runner = CliRunner()


def _write_config(tmp_path: Path, audit_path: Path) -> Path:
    config_path = tmp_path / "agentvanguard.yaml"
    config_path.write_text(yaml.safe_dump({"audit": {"path": str(audit_path)}}))
    return config_path


def _write_event(audit_path: Path, **overrides: object) -> dict:
    event = {
        "event_id": "11111111-1111-1111-1111-111111111111",
        "event_type": "authorization",
        "timestamp": "2026-06-18T00:00:00+00:00",
        "trace_id": "trace-abc",
        "session_id": "session-1",
        "action": "tool_call",
        "decision": "DENY",
        "risk_score": 0.9,
        "findings": [
            {
                "type": "secret",
                "detector": "secrets",
                "severity": "high",
                "message": "looks like an AWS key",
            }
        ],
        "reasons": ["tool 'send_email' requires approval and was auto-denied"],
        "payload": {},
    }
    event.update(overrides)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a") as f:
        f.write(json.dumps(event) + "\n")
    return event


def test_explain_prints_decision_breakdown_for_matching_trace_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    audit_path = tmp_path / "logs" / "audit.jsonl"
    config_path = _write_config(tmp_path, audit_path)
    _write_event(audit_path)

    result = runner.invoke(app, ["explain", "trace-abc", "--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert "DENY" in result.output
    assert "secret" in result.output
    assert "looks like an AWS key" in result.output
    assert "requires approval and was auto-denied" in result.output


def test_explain_unknown_trace_id_exits_nonzero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    audit_path = tmp_path / "logs" / "audit.jsonl"
    config_path = _write_config(tmp_path, audit_path)
    _write_event(audit_path)

    result = runner.invoke(app, ["explain", "does-not-exist", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "No audit event found" in result.output


def test_explain_missing_audit_file_exits_nonzero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    audit_path = tmp_path / "logs" / "audit.jsonl"
    config_path = _write_config(tmp_path, audit_path)

    result = runner.invoke(app, ["explain", "trace-abc", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "Audit log not found" in result.output
