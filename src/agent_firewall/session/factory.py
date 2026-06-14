"""`build_session_store(config) -> SessionStore` — selects the `SessionStore`
implementation based on `config.session_store.backend`."""

from __future__ import annotations

from agent_firewall.config.schema import Config
from agent_firewall.session.store import InMemorySessionStore, SessionStore


def build_session_store(config: Config) -> SessionStore:
    section = config.session_store

    if section.backend == "redis":
        from agent_firewall.session.redis_store import RedisSessionStore

        return RedisSessionStore(section.redis_url, key_prefix=section.key_prefix, ttl_seconds=section.ttl_seconds)

    return InMemorySessionStore()
