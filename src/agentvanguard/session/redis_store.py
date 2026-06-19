"""`RedisSessionStore` — `SessionStore` backed by Redis, for multi-replica
sidecar deployments where `InMemorySessionStore` (process-local) would let
each replica see a different `SessionState` for the same session.

Requires the `redis` package: `pip install 'agentvanguard[redis]'`.
"""

from __future__ import annotations

from agentvanguard.core.errors import ConfigError
from agentvanguard.core.models import SessionState

DEFAULT_KEY_PREFIX = "agentvanguard:session:"


class RedisSessionStore:
    """`SessionStore` protocol implementation using `redis-py`.

    `SessionState` is stored as a JSON string under `<key_prefix><session_id>`,
    with an optional TTL refreshed on every `put()`.

    Concurrency note: like `InMemorySessionStore`, this implementation does
    not itself lock around `get()`/`put()` -- Redis's per-key `SET`/`GET`
    are atomic individually, but the get-mutate-put sequence used by
    `Engine.authorize()` is only safe from races *within* one process,
    because `Engine` holds an in-process per-`session_id` lock across that
    whole sequence (see `Engine._lock_for_session`). That lock is not shared
    across replicas, so if two different replica processes both call
    `authorize()` for the *same* `session_id` at the same time, they can each
    `get()` the same starting `SessionState`, increment their own copy of
    its counters, and `put()` -- with the second `put()` overwriting the
    first rather than the counts summing. This is an accepted tradeoff for
    using a thin JSON-blob-per-key store rather than atomic Redis counters;
    multi-replica deployments needing exact enforcement of runtime limits
    under concurrent load on a single session should be aware of this.
    """

    def __init__(self, url: str, *, key_prefix: str = DEFAULT_KEY_PREFIX, ttl_seconds: int | None = None) -> None:
        # `redis-py` is an optional dependency (the `[redis]` extra) so that
        # the core package has no hard dependency on it; only deployments
        # that actually select `session_store.backend: redis` need it
        # installed.
        try:
            import redis
        except ImportError as exc:
            raise ConfigError(
                "session_store.backend: 'redis' requires the 'redis' package; "
                "install it with: pip install 'agentvanguard[redis]'"
            ) from exc

        # `decode_responses=True` makes the client return `str` (not
        # `bytes`) from `GET`, so `get()` below can pass the raw value
        # straight into `SessionState.model_validate_json` without manual
        # decoding.
        self._client = redis.Redis.from_url(url, decode_responses=True)
        # Namespaces every key this store touches (e.g.
        # "agentvanguard:session:") so it can share a Redis instance/database
        # with other unrelated data without key collisions.
        self.key_prefix = key_prefix
        # Optional time-to-live (seconds) applied to every `put()`; `None`
        # means keys never expire on their own. A TTL is useful to bound
        # memory growth from abandoned sessions that are never explicitly
        # cleaned up.
        self.ttl_seconds = ttl_seconds

    def _key(self, session_id: str) -> str:
        """Build the namespaced Redis key for `session_id`."""
        return f"{self.key_prefix}{session_id}"

    def get(self, session_id: str) -> SessionState:
        """Fetch and deserialize the `SessionState` JSON blob stored under
        this session's key, or return a fresh `SessionState` if the key
        doesn't exist (never seen before, or expired via `ttl_seconds`)."""
        raw = self._client.get(self._key(session_id))
        if raw is None:
            return SessionState(session_id=session_id)
        return SessionState.model_validate_json(raw)

    def put(self, session_state: SessionState) -> None:
        """Serialize `session_state` to JSON and overwrite its key in Redis.

        If `ttl_seconds` is configured, every `put()` resets the expiry
        (via `SET ... EX`) -- so the TTL is effectively "expire N seconds
        after the *last* write to this session," not a fixed expiry from
        first creation. This keeps active sessions alive indefinitely while
        still reclaiming storage for sessions that go idle.
        """
        key = self._key(session_state.session_id)
        value = session_state.model_dump_json()
        if self.ttl_seconds is not None:
            self._client.set(key, value, ex=self.ttl_seconds)
        else:
            self._client.set(key, value)
