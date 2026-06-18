"""Concurrency regression test for `Engine.authorize()`'s session-state
read-modify-write cycle (see `Engine._lock_for_session`)."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from agentvanguard import AgentVanguard
from agentvanguard.config.schema import Config
from agentvanguard.core.enums import ActionKind
from agentvanguard.core.models import PolicyInput


def test_concurrent_authorize_calls_for_same_session_do_not_lose_counter_updates(tmp_path: Path) -> None:
    """Two concurrent `authorize()` calls for the *same* `session_id` must
    not both read the same stale `tool_call_count` and have the second
    `put()` clobber the first's increment -- that would silently
    under-count usage and let more tool calls through than
    `max_tool_calls` permits. `Engine` must serialize the
    resolve -> mutate -> persist cycle per session."""

    config = Config(
        audit={"path": str(tmp_path / "logs" / "audit.jsonl")},
        runtime_limits={"max_tool_calls": 1000, "max_repeated_calls": 1000},
        tools={"lookup_order": {"action_type": "read", "risk_tier": "low"}},
    )
    firewall = AgentVanguard(config)
    session_id = "race-session"
    thread_count = 50

    original_get = firewall.engine.session_store.get

    def slow_get(sid: str):
        state = original_get(sid)
        time.sleep(0.005)
        return state

    firewall.engine.session_store.get = slow_get  # type: ignore[method-assign]

    barrier = threading.Barrier(thread_count)

    def call(i: int) -> None:
        barrier.wait()
        firewall.authorize(
            PolicyInput(
                action=ActionKind.TOOL_CALL,
                tool="lookup_order",
                arguments={"order_id": str(i)},
                session_id=session_id,
            )
        )

    threads = [threading.Thread(target=call, args=(i,)) for i in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final_state = original_get(session_id)
    assert final_state.tool_call_count == thread_count
