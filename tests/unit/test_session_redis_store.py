"""Unit tests for `agentvanguard.session.redis_store.RedisSessionStore` and
`agentvanguard.session.factory.build_session_store`, using `fakeredis` in
place of a real Redis server."""

from __future__ import annotations

import sys
from unittest.mock import patch

import fakeredis
import pytest

from agentvanguard.config.schema import Config
from agentvanguard.core.errors import ConfigError
from agentvanguard.core.models import SessionState
from agentvanguard.session.factory import build_session_store
from agentvanguard.session.redis_store import RedisSessionStore
from agentvanguard.session.store import InMemorySessionStore


@pytest.fixture()
def fake_redis_client() -> fakeredis.FakeRedis:
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture()
def redis_store(fake_redis_client: fakeredis.FakeRedis) -> RedisSessionStore:
    with patch("redis.Redis.from_url", return_value=fake_redis_client):
        return RedisSessionStore("redis://localhost:6379/0", ttl_seconds=60)


def test_get_unknown_session_returns_fresh_state(redis_store: RedisSessionStore) -> None:
    state = redis_store.get("session-1")

    assert state == SessionState(session_id="session-1")


def test_put_then_get_round_trips(redis_store: RedisSessionStore) -> None:
    state = SessionState(session_id="session-1", step_count=3, tool_call_count=1)

    redis_store.put(state)

    assert redis_store.get("session-1") == state


def test_put_sets_ttl(redis_store: RedisSessionStore, fake_redis_client: fakeredis.FakeRedis) -> None:
    redis_store.put(SessionState(session_id="session-1"))

    ttl = fake_redis_client.ttl(redis_store._key("session-1"))
    assert ttl > 0


def test_put_without_ttl_does_not_expire(fake_redis_client: fakeredis.FakeRedis) -> None:
    with patch("redis.Redis.from_url", return_value=fake_redis_client):
        store = RedisSessionStore("redis://localhost:6379/0", ttl_seconds=None)

    store.put(SessionState(session_id="session-1"))

    assert fake_redis_client.ttl(store._key("session-1")) == -1


def test_redis_session_store_requires_redis_package() -> None:
    with patch.dict(sys.modules, {"redis": None}):
        with pytest.raises(ConfigError):
            RedisSessionStore("redis://localhost:6379/0")


def test_build_session_store_defaults_to_in_memory() -> None:
    store = build_session_store(Config())

    assert isinstance(store, InMemorySessionStore)


def test_build_session_store_redis_backend(fake_redis_client: fakeredis.FakeRedis) -> None:
    config = Config(session_store={"backend": "redis", "redis_url": "redis://localhost:6379/0"})

    with patch("redis.Redis.from_url", return_value=fake_redis_client):
        store = build_session_store(config)

    assert isinstance(store, RedisSessionStore)
