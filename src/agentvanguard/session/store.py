"""`SessionStore` protocol + the default in-memory implementation.

`Engine.authorize()` resolves a `SessionState` for `PolicyInput.session_id`
(falling back to `PolicyInput.session_state` or a fresh state), runs the
session guard, then persists the updated state back via `put()`.

`InMemorySessionStore` is process-local and not shared across replicas — use
`agentvanguard.session.redis_store.RedisSessionStore` (same protocol, built
via `agentvanguard.session.factory.build_session_store`) for multi-replica
sidecar deployments.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agentvanguard.core.models import SessionState


@runtime_checkable
class SessionStore(Protocol):
    """Storage contract for `SessionState`, used by `Engine.authorize()` to
    read-modify-write the per-session runtime counters (step count,
    tool-call count, recent tool-call hashes) that the session guard enforces
    runtime limits (`max_steps`, `max_tool_calls`, `max_repeated_calls`)
    against.

    Concurrency contract: `get()`/`put()` themselves are not required to be
    atomic with respect to each other, and a `SessionStore` implementation
    is not expected to provide its own locking around the
    get-mutate-put sequence. Instead, `Engine` serializes the full
    resolve -> mutate -> persist sequence for a given `session_id` using its
    own per-session `threading.Lock` (see `Engine._lock_for_session`) before
    ever calling `get()`, so within one process concurrent `authorize()`
    calls for the *same* session never interleave their `get()`/`put()`
    pairs. That in-process lock does **not** extend across multiple
    replicas sharing a `RedisSessionStore` -- there is no cross-process
    coordination in this protocol, so multi-replica deployments can still
    race on the same session unless they add external coordination.
    """

    def get(self, session_id: str) -> SessionState:
        """Return the `SessionState` for `session_id`, or a fresh one if
        this is the first time it has been seen.

        Must never raise for an unknown `session_id` -- "no state yet" is
        represented by returning a newly constructed `SessionState`
        (counters at their defaults), not by raising or returning `None`,
        so callers can always treat the return value as the session's
        current state.
        """
        ...

    def put(self, session_state: SessionState) -> None:
        """Persist `session_state` (keyed by `session_state.session_id`),
        overwriting whatever was previously stored for that session id.

        This is a full replace, not a merge: callers are expected to have
        already produced the complete, updated `SessionState` (e.g. by
        mutating the object returned from `get()`) before calling `put()`.
        """
        ...


class InMemorySessionStore:
    """Process-local `dict`-backed `SessionStore`.

    The default backend (`config.session_store.backend` unset or not
    `"redis"`). State lives only in this process's memory: it is lost on
    restart and is **not** visible to other processes/replicas, which is why
    multi-replica sidecar deployments should use `RedisSessionStore`
    instead (selected via `agentvanguard.session.factory.build_session_store`).
    """

    def __init__(self) -> None:
        # Plain dict keyed by session_id; no locking here because `Engine`
        # already serializes access per session_id via its own lock before
        # calling into this store (see `SessionStore`'s concurrency
        # contract above).
        self._sessions: dict[str, SessionState] = {}

    def get(self, session_id: str) -> SessionState:
        # `.get(..., default)` returns a brand-new `SessionState` (all
        # counters at zero) without inserting it into `_sessions` -- the
        # session is only actually recorded once `put()` is called with it,
        # e.g. after the session guard has updated its counters.
        return self._sessions.get(session_id, SessionState(session_id=session_id))

    def put(self, session_state: SessionState) -> None:
        # Overwrite (not merge) the entry for this session_id, matching the
        # `SessionStore.put` contract.
        self._sessions[session_state.session_id] = session_state
