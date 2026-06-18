"""Unit tests for `agentvanguard.control_plane.sources` --
`LocalFileSource` and `HttpPolicyBundleSource` (mocked HTTP)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from agentvanguard.config.defaults import get_default_config
from agentvanguard.config.schema import Config
from agentvanguard.control_plane import HttpPolicyBundleSource, LocalFileSource
from agentvanguard.core.errors import ConfigError


class _FakeResponse:
    def __init__(self, body: bytes, content_type: str) -> None:
        self._body = body
        self.headers = {"Content-Type": content_type}

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _patch_urlopen(response: _FakeResponse | Exception) -> Any:
    def _urlopen(*args: object, **kwargs: object) -> _FakeResponse:
        if isinstance(response, Exception):
            raise response
        return response

    return patch("agentvanguard.control_plane.sources.urllib.request.urlopen", side_effect=_urlopen)


def test_local_file_source_fetch(tmp_path: Path) -> None:
    config_path = tmp_path / "agentvanguard.yaml"
    config_path.write_text("firewall:\n  fail_closed: false\n")

    config = LocalFileSource(str(config_path)).fetch()

    assert isinstance(config, Config)
    assert config.firewall.fail_closed is False


def test_http_policy_bundle_source_fetch_json() -> None:
    body = json.dumps({"firewall": {"fail_closed": False}}).encode("utf-8")
    source = HttpPolicyBundleSource("http://policy.example/bundle")

    with _patch_urlopen(_FakeResponse(body, "application/json")):
        config = source.fetch()

    assert config.firewall.fail_closed is False
    assert source._cached is config


def test_http_policy_bundle_source_fetch_yaml() -> None:
    body = b"firewall:\n  fail_closed: false\n"
    source = HttpPolicyBundleSource("http://policy.example/bundle")

    with _patch_urlopen(_FakeResponse(body, "application/yaml")):
        config = source.fetch()

    assert config.firewall.fail_closed is False


def test_http_policy_bundle_source_non_mapping_raises_config_error() -> None:
    body = json.dumps([1, 2, 3]).encode("utf-8")
    source = HttpPolicyBundleSource("http://policy.example/bundle")

    with _patch_urlopen(_FakeResponse(body, "application/json")):
        with pytest.raises(ConfigError):
            source.fetch()


def test_http_policy_bundle_source_cross_reference_error() -> None:
    body = json.dumps(
        {"workflows": {"finance": {"allowed_tools": ["does_not_exist"]}}}
    ).encode("utf-8")
    source = HttpPolicyBundleSource("http://policy.example/bundle")

    with _patch_urlopen(_FakeResponse(body, "application/json")):
        with pytest.raises(ConfigError):
            source.fetch()


def test_http_policy_bundle_source_fetch_failure_closed_raises() -> None:
    source = HttpPolicyBundleSource("http://policy.example/bundle", fail_mode="closed")

    with _patch_urlopen(OSError("connection refused")):
        with pytest.raises(ConfigError):
            source.fetch()


def test_http_policy_bundle_source_fetch_failure_open_falls_back_to_cache() -> None:
    body = json.dumps({"firewall": {"fail_closed": False}}).encode("utf-8")
    source = HttpPolicyBundleSource("http://policy.example/bundle", fail_mode="open")

    with _patch_urlopen(_FakeResponse(body, "application/json")):
        first = source.fetch()

    with _patch_urlopen(OSError("connection refused")):
        second = source.fetch()

    assert second is first


def test_http_policy_bundle_source_fetch_failure_open_no_cache_returns_default() -> None:
    source = HttpPolicyBundleSource("http://policy.example/bundle", fail_mode="open")

    with _patch_urlopen(OSError("connection refused")):
        config = source.fetch()

    assert config == get_default_config()
