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
    """Raises `VanguardBlockedError(decision)` for any non-final decision.

    `REQUIRE_USER_CONFIRMATION` is treated the same as `DENY` here because by
    the time `Engine.authorize()` returns, the `ApprovalProvider` has already
    had its chance to downgrade an approved confirmation to `ALLOW`/
    `ALLOW_WITH_MODIFICATIONS` -- a `Decision` still carrying
    `REQUIRE_USER_CONFIRMATION` at this point means approval was refused (or
    `auto_deny` was used), so callers should treat it as a block.
    """

    if decision.decision in (DecisionAction.DENY, DecisionAction.REQUIRE_USER_CONFIRMATION):
        raise VanguardBlockedError(decision)


def _pop_context(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Removes and returns the `_context` kwarg (if any) from a call's
    keyword arguments, so it never reaches the wrapped tool/agent function
    itself. Returns `{}` if no context was supplied."""

    return kwargs.pop("_context", {}) or {}


class AgentVanguard:
    """The public entry point: construct via `from_config`, then use
    `authorize`/`check_output`/`tool`/`wrap_tool`/`wrap_agent`."""

    def __init__(self, config: Config) -> None:
        self.config = config
        # One Engine per AgentVanguard instance -- holds the detector
        # registry, tool manifests, session store, approval provider, and
        # audit logger built from this `config`.
        self.engine = Engine(config)

    @classmethod
    def from_config(cls, path: str | None = None) -> "AgentVanguard":
        """Loads `agentvanguard.yaml` (or the path/env-var/default fallback
        chain implemented by `config.loader.load`) and constructs the
        firewall around it. This is the normal way to obtain an
        `AgentVanguard` instance."""

        return cls(load(path))

    def authorize(self, policy_input: PolicyInput) -> Decision:
        """Pass-through to `Engine.authorize` for callers that want full
        control over the `PolicyInput` (e.g. a custom `action`/`workflow`/
        `actor` combination not covered by the convenience methods below)."""

        return self.engine.authorize(policy_input)

    def check_output(
        self, output: str, destination: str = "plain", session_id: str | None = None
    ) -> Decision:
        """Convenience wrapper around `authorize(action="output")`: runs the
        DLP detectors over `output` and returns a `Decision` whose
        `redacted_content` (if set) is the sanitized text to use instead.
        `destination` selects context-aware sanitization in the output guard
        (e.g. `"html"` escapes, `"shell"` shell-quotes) on top of DLP
        redaction."""

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
            # Look up a manifest declared under `tools:` in config, or
            # registered by an earlier `wrap_tool`/`@firewall.tool` call --
            # fail loudly rather than silently allowing an unrisk-assessed tool.
            existing = self.engine.tool_manifests.get(manifest)
            if existing is None:
                raise ConfigError(
                    f"no ToolManifest registered for tool '{manifest}'; declare it under "
                    f"`tools:` in agentvanguard.yaml or pass a ToolManifest instance to wrap_tool()"
                )
            manifest = existing
        else:
            # A `ToolManifest` instance was passed directly -- register it on
            # the engine now so the tool-call guard can find it by name later.
            self.engine.register_tool(manifest)

        # `fn` may be sync or async; build a wrapper with matching iscoroutine-
        # ness so callers (and frameworks introspecting the function) see the
        # same calling convention as the original `fn`. Both wrappers follow
        # the same three steps: pop `_context` -> authorize the call -> run
        # `fn` only if authorized -> guard the result before returning it.
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                context = _pop_context(kwargs)
                decision = self._authorize_tool_call(manifest, kwargs, context)
                _enforce(decision)  # raises VanguardBlockedError if not ALLOW(_WITH_MODIFICATIONS)
                result = await fn(*args, **kwargs)
                return self._guard_tool_result(result, context)

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            context = _pop_context(kwargs)
            decision = self._authorize_tool_call(manifest, kwargs, context)
            _enforce(decision)  # raises VanguardBlockedError if not ALLOW(_WITH_MODIFICATIONS)
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
        """Builds the `action="tool_call"` `PolicyInput` for one call to a
        `wrap_tool`-wrapped function and runs it through the engine.
        `context` supplies the caller/session metadata (`actor`, `agent`,
        `workflow`, `session_id`); `arguments` is the call's own kwargs,
        passed straight through to the tool-call guard for schema/SSRF/
        path-traversal/egress/credential checks."""

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
        """Runs a tool's return value through the output guard (DLP) before
        handing it back to the caller -- tool results can themselves leak
        secrets/PII (e.g. a database lookup returning a stored card number)
        back into the agent's context. Non-string results (most tool outputs
        in typed pipelines) pass through unchecked, since the DLP detectors
        operate on text."""

        if not isinstance(result, str):
            return result

        decision = self.check_output(result, destination="plain", session_id=context.get("session_id"))
        _enforce(decision)  # a DENY here means an unredacted critical secret was found
        return decision.redacted_content if decision.redacted_content is not None else result


class SafeAgent:
    """Returned by `AgentVanguard.wrap_agent`. Duck-types `run`/`invoke`/
    `__call__` on the wrapped agent: the first positional argument is treated
    as the ingress text, the return value as the egress text."""

    def __init__(self, firewall: AgentVanguard, agent: Any) -> None:
        self._firewall = firewall
        self._agent = agent

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Mediated equivalent of `agent.run(...)`."""

        return self._guarded_call("run", *args, **kwargs)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        """Mediated equivalent of `agent.invoke(...)` (LangChain-style agents)."""

        return self._guarded_call("invoke", *args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Mediated equivalent of calling `agent(...)` directly."""

        return self._guarded_call("__call__", *args, **kwargs)

    def _guarded_call(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Shared implementation behind `run`/`invoke`/`__call__`: checks
        ingress, calls the wrapped agent's `method_name` with the
        (possibly redacted) sanitized input, then checks egress on the
        return value before handing it back to the caller."""

        context = _pop_context(kwargs)
        if not args:
            raise TypeError(f"{method_name}() requires at least one positional argument (the input text)")
        # By convention the first positional argument is the user-facing
        # input text; any remaining positional args pass through untouched.
        input_text, *rest = args

        # Ingress check: scan the incoming text for prompt injection/PII/
        # secrets before the underlying agent (and the LLM behind it) ever
        # sees it.
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
        _enforce(ingress_decision)  # raises VanguardBlockedError on DENY/REQUIRE_USER_CONFIRMATION
        sanitized_input = ingress_decision.redacted_content if ingress_decision.redacted_content is not None else input_text

        # Run the wrapped agent's method with the sanitized input. Note this
        # call is NOT itself mediated for any tool calls the agent makes
        # internally -- see the class docstring on `wrap_agent`.
        method = getattr(self._agent, method_name)
        result = method(sanitized_input, *rest, **kwargs)

        # Egress check: scan the agent's reply for PII/secrets before
        # returning it to the caller. Non-string results are stringified
        # only for the purposes of this scan; the original (typed) `result`
        # is still what gets returned unless it was a string that needed redaction.
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
        _enforce(output_decision)  # raises VanguardBlockedError on DENY/REQUIRE_USER_CONFIRMATION
        if output_decision.redacted_content is not None and isinstance(result, str):
            return output_decision.redacted_content
        return result
