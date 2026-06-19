"""`Engine` — the single, shared, synchronous, in-memory policy core.

Every integration surface (SDK, tool-broker, ASGI middleware, sidecar HTTP
handlers) constructs a `PolicyInput` and calls `Engine.authorize()`. No
integration surface re-implements policy logic — this is the architectural
invariant of agentvanguard.

`authorize()`:

1. Resolves the `SessionState` for `PolicyInput.session_id` (or uses
   `PolicyInput.session_state` if the caller supplies it directly).
2. Dispatches to the relevant guard stage(s) via `PolicyEvaluator.evaluate`,
   producing `Verdict[]`.
3. Aggregates `Verdict[]` into one `Decision` (worst-action-wins).
4. If the aggregated decision is `REQUIRE_USER_CONFIRMATION`, consults the
   configured `ApprovalProvider`; an approval downgrades the decision to
   `ALLOW`/`ALLOW_WITH_MODIFICATIONS`.
5. Updates and persists `SessionState`, writes an `AuditEvent`, and returns
   the final `Decision`.
"""

from __future__ import annotations

import threading
import time

from agentvanguard.approval import build_approval_provider
from agentvanguard.audit.logger import AuditLogger
from agentvanguard.config.schema import Config
from agentvanguard.core.enums import ActionKind, DecisionAction
from agentvanguard.core.models import Decision, PolicyInput, SessionState, ToolManifest
from agentvanguard.detectors.registry import DetectorRegistry
from agentvanguard.guards.session_guard import call_hash
from agentvanguard.observability import metrics, tracing
from agentvanguard.policy.evaluator import PolicyEvaluator
from agentvanguard.policy.risk import aggregate
from agentvanguard.session.factory import build_session_store


class Engine:
    """The shared policy core. One `Engine` per process/config; cheap to
    construct (no I/O beyond the audit sink)."""

    def __init__(self, config: Config) -> None:
        self.config = config
        # Active detector set (injection/PII/secrets/exfil) built once from config.
        self.detectors = DetectorRegistry.from_config(config)
        # Tool name -> ToolManifest, seeded from `tools:` in config; `register_tool`
        # adds entries at runtime for tools declared only via `wrap_tool`/`@firewall.tool`.
        self.tool_manifests: dict[str, ToolManifest] = config.tool_manifests()
        # Dispatches a `PolicyInput` to the right guard(s) and returns `Verdict[]`.
        self.evaluator = PolicyEvaluator(config)
        # Per-session runtime counters (in-memory or Redis, per `session_store.backend`).
        self.session_store = build_session_store(config)
        # Resolves REQUIRE_USER_CONFIRMATION decisions (auto_deny by default).
        self.approval = build_approval_provider(config)
        # Fans out one AuditEvent per `authorize()` call to the configured sink(s).
        self.audit = AuditLogger.from_config(config, self.detectors)
        # Per-session-id locks (see `_lock_for_session`) and the lock that
        # guards mutation of the `_session_locks` dict itself.
        self._session_locks: dict[str, threading.Lock] = {}
        self._session_locks_guard = threading.Lock()

    def register_tool(self, manifest: ToolManifest) -> None:
        """Register (or overwrite) a `ToolManifest` at runtime — used by
        `AgentVanguard.wrap_tool`/`@firewall.tool` for tools that aren't
        declared in `agentvanguard.yaml`."""

        self.tool_manifests[manifest.name] = manifest

    def _lock_for_session(self, session_id: str) -> threading.Lock:
        """A dedicated `Lock` per `session_id`, so concurrent `authorize()`
        calls for *different* sessions never block each other, while calls
        for the *same* session are serialized end-to-end (resolve -> mutate
        -> persist) -- closing the read-modify-write race that would
        otherwise let two concurrent requests for one session both read the
        same counters and the second `put()` clobber the first's increment,
        defeating `max_steps`/`max_tool_calls`/`max_repeated_calls`.

        This only serializes calls within this process; a `RedisSessionStore`
        shared across multiple replicas still needs its own per-replica lock
        scope, since there is no cross-process coordination here.
        """

        with self._session_locks_guard:
            lock = self._session_locks.get(session_id)
            if lock is None:
                lock = threading.Lock()
                self._session_locks[session_id] = lock
            return lock

    def authorize(self, policy_input: PolicyInput) -> Decision:
        """The single entry point every integration surface calls. Builds a
        `Decision` for one `PolicyInput`, mutating session state and writing
        an audit event as a side effect. See the module docstring for the
        numbered step-by-step flow this method implements."""

        start = time.monotonic()
        # `session_id` defaults to a shared "default" bucket so single-session
        # demos/tests that never pass one still get runtime-limit tracking.
        session_key = policy_input.session_id or "default"

        with tracing.span("agentvanguard.authorize", action=policy_input.action.value):
            # Serialize everything for this session_id (read counters -> evaluate
            # -> mutate counters -> persist) so concurrent calls can't race on
            # the same session's runtime-limit counters (see `_lock_for_session`).
            with self._lock_for_session(session_key):
                # Step 1: load this session's cumulative counters (or use the
                # caller-supplied `SessionState` if one was passed explicitly).
                session_state = self._resolve_session_state(policy_input)

                # Step 2: run the guard(s) relevant to `policy_input.action`.
                verdicts = self.evaluator.evaluate(policy_input, self.detectors, self.tool_manifests, session_state)
                # Step 3: reduce the per-stage Verdicts to one Decision
                # (worst-action-wins; reasons/redactions/risk_score combined).
                decision = aggregate(verdicts)

                # Step 4: a REQUIRE_USER_CONFIRMATION decision is not final --
                # ask the configured ApprovalProvider. An approval downgrades
                # to ALLOW (or ALLOW_WITH_MODIFICATIONS if there were pending
                # redactions); a refusal leaves REQUIRE_USER_CONFIRMATION in
                # place, which callers treat as a block (see `firewall._enforce`).
                if decision.decision == DecisionAction.REQUIRE_USER_CONFIRMATION:
                    if self.approval.request_approval(decision, policy_input):
                        downgraded = (
                            DecisionAction.ALLOW_WITH_MODIFICATIONS if decision.redactions else DecisionAction.ALLOW
                        )
                        decision = decision.model_copy(update={"decision": downgraded})

                # Step 5: persist updated counters and write the audit trail
                # before releasing the per-session lock, so the next call for
                # this session always observes a consistent, up-to-date state.
                self._update_session_state(session_state, policy_input, decision)
                self.audit.log(policy_input, decision, verdicts)

        # Metrics are recorded outside the lock -- they're independent of
        # session state and shouldn't hold up the next call for this session.
        metrics.record_decision(policy_input.action.value, decision.decision.value, time.monotonic() - start)
        return decision

    def _resolve_session_state(self, policy_input: PolicyInput) -> SessionState:
        """Returns the `SessionState` to evaluate against: the caller's own
        (if `PolicyInput.session_state` was supplied directly, bypassing the
        store entirely), otherwise whatever is currently stored for this
        `session_id` (a fresh, zeroed `SessionState` if none exists yet)."""

        if policy_input.session_state is not None:
            return policy_input.session_state
        return self.session_store.get(policy_input.session_id or "default")

    def _update_session_state(
        self, session_state: SessionState, policy_input: PolicyInput, decision: Decision
    ) -> None:
        """Increments this session's runtime counters for the action just
        evaluated, then persists the result. Every action counts toward
        `step_count`; `tool_call` actions additionally count toward
        `tool_call_count` and, only if the call wasn't denied, get a stable
        hash of `(tool, arguments)` appended to `recent_tool_call_hashes` --
        the list `session_guard.evaluate()` checks for repetition-loop
        detection. Denied calls are intentionally excluded so that a tool a
        caller keeps retrying *unsuccessfully* doesn't itself trip the
        repeated-call limit on top of whatever already blocked it."""

        session_state.step_count += 1

        if policy_input.action == ActionKind.TOOL_CALL:
            session_state.tool_call_count += 1
            if policy_input.tool and decision.decision != DecisionAction.DENY:
                session_state.recent_tool_call_hashes.append(
                    call_hash(policy_input.tool, policy_input.arguments)
                )

        self.session_store.put(session_state)
