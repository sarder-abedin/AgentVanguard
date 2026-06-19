"""`build_session_store(config) -> SessionStore` — selects the `SessionStore`
implementation based on `config.session_store.backend`."""

from __future__ import annotations

from agentvanguard.config.schema import Config
from agentvanguard.session.store import InMemorySessionStore, SessionStore


def build_session_store(config: Config) -> SessionStore:
    """Construct the `SessionStore` implementation named by
    `config.session_store.backend`, called once by `Engine.__init__` to
    build the store the whole `Engine` instance shares.

    `"redis"` selects `RedisSessionStore` for deployments where multiple
    sidecar replicas must all observe the same `SessionState` for a given
    `session_id` (otherwise each replica would maintain its own counters and
    runtime limits like `max_steps` could be bypassed by load-balancing
    requests across replicas). Any other value (including the default)
    falls back to the process-local `InMemorySessionStore`, suitable for a
    single-process/single-replica deployment or for tests.

    The import of `RedisSessionStore` is deferred to inside the `"redis"`
    branch so that the optional `redis` dependency is only required when
    that backend is actually selected -- configs that never use Redis never
    pay the import cost or need the package installed.
    """

    section = config.session_store

    if section.backend == "redis":
        from agentvanguard.session.redis_store import RedisSessionStore

        return RedisSessionStore(section.redis_url, key_prefix=section.key_prefix, ttl_seconds=section.ttl_seconds)

    return InMemorySessionStore()
