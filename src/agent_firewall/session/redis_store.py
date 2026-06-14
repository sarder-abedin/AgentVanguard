"""`RedisSessionStore` — `SessionStore` backed by Redis, for multi-replica
sidecar deployments where `InMemorySessionStore` (process-local) would let
each replica see a different `SessionState` for the same session.

Requires the `redis` package: `pip install 'agent-firewall[redis]'`.
"""

from __future__ import annotations

from agent_firewall.core.errors import ConfigError
from agent_firewall.core.models import SessionState

DEFAULT_KEY_PREFIX = "agent_firewall:session:"


class RedisSessionStore:
    """`SessionStore` protocol implementation using `redis-py`.

    `SessionState` is stored as a JSON string under `<key_prefix><session_id>`,
    with an optional TTL refreshed on every `put()`.
    """

    def __init__(self, url: str, *, key_prefix: str = DEFAULT_KEY_PREFIX, ttl_seconds: int | None = None) -> None:
        try:
            import redis
        except ImportError as exc:
            raise ConfigError(
                "session_store.backend: 'redis' requires the 'redis' package; "
                "install it with: pip install 'agent-firewall[redis]'"
            ) from exc

        self._client = redis.Redis.from_url(url, decode_responses=True)
        self.key_prefix = key_prefix
        self.ttl_seconds = ttl_seconds

    def _key(self, session_id: str) -> str:
        return f"{self.key_prefix}{session_id}"

    def get(self, session_id: str) -> SessionState:
        raw = self._client.get(self._key(session_id))
        if raw is None:
            return SessionState(session_id=session_id)
        return SessionState.model_validate_json(raw)

    def put(self, session_state: SessionState) -> None:
        key = self._key(session_state.session_id)
        value = session_state.model_dump_json()
        if self.ttl_seconds is not None:
            self._client.set(key, value, ex=self.ttl_seconds)
        else:
            self._client.set(key, value)
