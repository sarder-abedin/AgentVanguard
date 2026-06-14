"""`SessionStore` protocol + the default in-memory implementation.

`Engine.authorize()` resolves a `SessionState` for `PolicyInput.session_id`
(falling back to `PolicyInput.session_state` or a fresh state), runs the
session guard, then persists the updated state back via `put()`.

`InMemorySessionStore` is process-local and not shared across replicas — use
`agent_firewall.session.redis_store.RedisSessionStore` (same protocol, built
via `agent_firewall.session.factory.build_session_store`) for multi-replica
sidecar deployments.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_firewall.core.models import SessionState


@runtime_checkable
class SessionStore(Protocol):
    def get(self, session_id: str) -> SessionState:
        """Return the `SessionState` for `session_id`, or a fresh one if
        this is the first time it has been seen."""
        ...

    def put(self, session_state: SessionState) -> None:
        """Persist `session_state` (keyed by `session_state.session_id`)."""
        ...


class InMemorySessionStore:
    """Process-local `dict`-backed `SessionStore`."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}

    def get(self, session_id: str) -> SessionState:
        return self._sessions.get(session_id, SessionState(session_id=session_id))

    def put(self, session_state: SessionState) -> None:
        self._sessions[session_state.session_id] = session_state
