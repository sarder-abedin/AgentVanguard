"""`AgentVanguard` — the public SDK / tool-broker API.

Every method here builds a `PolicyInput` and calls the shared `Engine` —
this module contains no policy logic of its own.

Both `wrap_tool`/`@firewall.tool` and `wrap_agent` accept an optional
`_context` keyword argument at call time:

    safe_tool(amount=100, _context={"actor": actor, "agent": agent_identity,
                                     "workflow": "finance_invoice_review",
                                     "session_id": "session-123"})

`_context` carries the caller/session metadata the engine needs
(`Actor`, `AgentIdentity`, `workflow`, `session_id`) without colliding with
the wrapped function's own parameters. All keys are optional.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any

from agentvanguard.config.loader import load
from agentvanguard.config.schema import Config
from agentvanguard.core.enums import ActionKind, DecisionAction
from agentvanguard.core.errors import ConfigError, VanguardBlockedError
from agentvanguard.core.models import Decision, PolicyInput, ToolManifest
from agentvanguard.engine import Engine


def _enforce(decision: Decision) -> None:
    if decision.decision in (DecisionAction.DENY, DecisionAction.REQUIRE_USER_CONFIRMATION):
        raise VanguardBlockedError(decision)


def _pop_context(kwargs: dict[str, Any]) -> dict[str, Any]:
    return kwargs.pop("_context", {}) or {}


class AgentVanguard:
    """The public entry point: construct via `from_config`, then use
    `authorize`/`check_output`/`tool`/`wrap_tool`/`wrap_agent`."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.engine = Engine(config)

    @classmethod
    def from_config(cls, path: str | None = None) -> "AgentVanguard":
        return cls(load(path))

    def authorize(self, policy_input: PolicyInput) -> Decision:
        return self.engine.authorize(policy_input)

    def check_output(
        self, output: str, destination: str = "plain", session_id: str | None = None
    ) -> Decision:
        return self.engine.authorize(
            PolicyInput(
                action=ActionKind.OUTPUT,
                content=output,
                arguments={"destination": destination},
                session_id=session_id,
            )
        )

    def tool(self, manifest: ToolManifest) -> Callable[[Callable], Callable]:
        """Decorator form of `wrap_tool`:

            @firewall.tool(manifest=ToolManifest(name="send_email", ...))
            def send_email(to: str, body: str) -> str: ...
        """

        def decorator(fn: Callable) -> Callable:
            return self.wrap_tool(manifest, fn)

        return decorator

    def wrap_tool(self, manifest: ToolManifest | str, fn: Callable) -> Callable:
        """Wrap `fn` (sync or async) so every call is authorized as
        `action="tool_call"` before running, and the result is run through
        the output guard (DLP) before being returned.

        If `manifest` is a string, it must already be registered (either via
        a `ToolManifest` instance previously passed here, or declared under
        `tools:` in `agentvanguard.yaml`).
        """

        if isinstance(manifest, str):
            existing = self.engine.tool_manifests.get(manifest)
            if existing is None:
                raise ConfigError(
                    f"no ToolManifest registered for tool '{manifest}'; declare it under "
                    f"`tools:` in agentvanguard.yaml or pass a ToolManifest instance to wrap_tool()"
                )
            manifest = existing
        else:
            self.engine.register_tool(manifest)

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                context = _pop_context(kwargs)
                decision = self._authorize_tool_call(manifest, kwargs, context)
                _enforce(decision)
                result = await fn(*args, **kwargs)
                return self._guard_tool_result(result, context)

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            context = _pop_context(kwargs)
            decision = self._authorize_tool_call(manifest, kwargs, context)
            _enforce(decision)
            result = fn(*args, **kwargs)
            return self._guard_tool_result(result, context)

        return sync_wrapper

    def wrap_async_tool(self, manifest: ToolManifest | str, fn: Callable) -> Callable:
        """Alias of `wrap_tool` for call sites that want to make the async
        contract explicit. `wrap_tool` already auto-detects coroutine
        functions via `inspect.iscoroutinefunction`."""

        return self.wrap_tool(manifest, fn)

    def wrap_agent(self, agent: Any) -> "SafeAgent":
        """Wrap an agent object so its `run`/`invoke`/`__call__` entry point
        is checked by the input guard (ingress) and output guard (egress).

        **This does not mediate tool calls made *inside* the agent** — tools
        must also be registered with `wrap_tool`/`@firewall.tool` for
        per-tool-call policy enforcement. `wrap_agent` + `wrap_tool` together
        give full ingress/action/egress coverage; `wrap_agent` alone only
        covers the agent's overall input/output.
        """

        return SafeAgent(self, agent)

    def _authorize_tool_call(
        self, manifest: ToolManifest, arguments: dict[str, Any], context: dict[str, Any]
    ) -> Decision:
        return self.engine.authorize(
            PolicyInput(
                action=ActionKind.TOOL_CALL,
                actor=context.get("actor"),
                agent=context.get("agent"),
                workflow=context.get("workflow"),
                tool=manifest.name,
                arguments=arguments,
                content=context.get("content"),
                session_id=context.get("session_id"),
            )
        )

    def _guard_tool_result(self, result: Any, context: dict[str, Any]) -> Any:
        if not isinstance(result, str):
            return result

        decision = self.check_output(result, destination="plain", session_id=context.get("session_id"))
        _enforce(decision)
        return decision.redacted_content if decision.redacted_content is not None else result


class SafeAgent:
    """Returned by `AgentVanguard.wrap_agent`. Duck-types `run`/`invoke`/
    `__call__` on the wrapped agent: the first positional argument is treated
    as the ingress text, the return value as the egress text."""

    def __init__(self, firewall: AgentVanguard, agent: Any) -> None:
        self._firewall = firewall
        self._agent = agent

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._guarded_call("run", *args, **kwargs)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        return self._guarded_call("invoke", *args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._guarded_call("__call__", *args, **kwargs)

    def _guarded_call(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        context = _pop_context(kwargs)
        if not args:
            raise TypeError(f"{method_name}() requires at least one positional argument (the input text)")
        input_text, *rest = args

        ingress_decision = self._firewall.authorize(
            PolicyInput(
                action=ActionKind.INGRESS,
                actor=context.get("actor"),
                agent=context.get("agent"),
                workflow=context.get("workflow"),
                content=input_text,
                session_id=context.get("session_id"),
            )
        )
        _enforce(ingress_decision)
        sanitized_input = ingress_decision.redacted_content if ingress_decision.redacted_content is not None else input_text

        method = getattr(self._agent, method_name)
        result = method(sanitized_input, *rest, **kwargs)

        output_text = result if isinstance(result, str) else str(result)
        output_decision = self._firewall.authorize(
            PolicyInput(
                action=ActionKind.OUTPUT,
                actor=context.get("actor"),
                agent=context.get("agent"),
                workflow=context.get("workflow"),
                content=output_text,
                session_id=context.get("session_id"),
            )
        )
        if output_decision.decision == DecisionAction.DENY:
            raise VanguardBlockedError(output_decision)
        if output_decision.redacted_content is not None and isinstance(result, str):
            return output_decision.redacted_content
        return result
