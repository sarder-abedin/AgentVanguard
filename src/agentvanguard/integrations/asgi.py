"""`AgentVanguardMiddleware` -- pure ASGI middleware that mediates an
existing app's HTTP traffic through `Engine.authorize()`.

For each HTTP request/response cycle:

1. Buffers the request body (up to `max_body_bytes`) and, if it decodes as
   UTF-8 text, runs `action=ingress` over it. A `DENY` short-circuits with a
   `403` JSON response (fail-closed); otherwise the `Decision` is attached to
   `scope["state"]["agentvanguard_ingress"]` (readable as
   `request.state.agentvanguard_ingress` in Starlette/FastAPI) and the
   request is replayed to the wrapped app unchanged.
2. Buffers the response body and, for 2xx responses that decode as UTF-8
   text, runs `action=output` over it. A `DENY` short-circuits with a `502`;
   `ALLOW_WITH_MODIFICATIONS` rewrites the body (and `Content-Length`) to the
   redacted text.

Bodies that exceed `max_body_bytes` are **not** silently passed through
unmediated -- fail-closed applies here too, so an oversized body is rejected
(`413` on ingress, `502` on output) rather than skipping inspection. Non-UTF-8
bodies (binary payloads) are not text-inspectable and pass through unchecked,
since the detectors only operate on text. Because the whole response body is
buffered before any of it is sent downstream, this middleware is **not**
suitable for streaming responses (e.g. SSE) -- use the sidecar
(`/v1/check-output`) for those instead.

    from agentvanguard import AgentVanguard
    from agentvanguard.integrations.asgi import AgentVanguardMiddleware

    firewall = AgentVanguard.from_config("agentvanguard.yaml")
    app = AgentVanguardMiddleware(app, firewall)
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from agentvanguard.core.enums import ActionKind, DecisionAction
from agentvanguard.core.models import Decision, PolicyInput
from agentvanguard.firewall import AgentVanguard

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


class AgentVanguardMiddleware:
    """ASGI middleware mediating ingress/egress through `Engine.authorize()`.

    Wrap any ASGI 3 application (FastAPI, Starlette, raw ASGI):

        app = AgentVanguardMiddleware(app, firewall)
    """

    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        firewall: AgentVanguard,
        *,
        max_body_bytes: int = 1_000_000,
        check_ingress: bool = True,
        check_output: bool = True,
    ) -> None:
        """
        Args:
            app: The wrapped ASGI 3 application to mediate.
            firewall: The shared `AgentVanguard` (and therefore `Engine`)
                used to authorize each request/response body.
            max_body_bytes: Per-direction buffering cap; bodies larger than
                this are rejected fail-closed (413 on ingress, 502 on
                output) rather than passed through uninspected.
            check_ingress: If False, skip the request-body `action=ingress`
                check entirely (still replays the body to `app` unchanged).
            check_output: If False, skip the response-body `action=output`
                check and buffering -- responses (including streaming ones)
                are relayed straight through via the original `send`.
        """

        self.app = app
        self.firewall = firewall
        self.max_body_bytes = max_body_bytes
        self.check_ingress = check_ingress
        self.check_output = check_output

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI entry point invoked once per connection/request by the
        server. Non-HTTP scopes (e.g. `lifespan`, `websocket`) are passed
        straight through unmediated -- only HTTP request/response cycles are
        inspected.
        """

        if scope["type"] != "http":
            # Only HTTP traffic is mediated; e.g. websocket/lifespan scopes
            # pass straight through to the wrapped app.
            await self.app(scope, receive, send)
            return

        # Drain the entire request body up front (see `_read_body`) so it
        # can be decoded and scanned as one block of text before the wrapped
        # app sees any of it.
        body, body_messages, truncated = await _read_body(receive, self.max_body_bytes)

        if self.check_ingress and body:
            if truncated:
                # Fail-closed: a body larger than max_body_bytes cannot be
                # safely inspected, so it is rejected outright (413) rather
                # than allowed through unchecked.
                await _send_json(send, 413, _oversized_payload("request"))
                return
            text = _decode(body)
            if text is not None:
                # Binary/non-UTF-8 bodies are not text-inspectable by the
                # detectors and are left unchecked (no `else` branch here);
                # only decodable text bodies reach `Engine.authorize()`.
                decision = self.firewall.authorize(PolicyInput(action=ActionKind.INGRESS, content=text))
                if decision.decision == DecisionAction.DENY:
                    # DENY short-circuits the whole request: the wrapped app
                    # is never invoked, and the caller gets a 403 with the
                    # decision's reasons/trace_id instead of a real response.
                    await _send_json(send, 403, _blocked_payload(decision))
                    return
                # ALLOW / ALLOW_WITH_MODIFICATIONS / REQUIRE_USER_CONFIRMATION
                # all let the request proceed; the Decision is exposed to the
                # wrapped app via scope["state"] so a route handler can read
                # `request.state.agentvanguard_ingress` if it wants to react
                # to redactions or confirmation requirements itself. Note
                # that unlike the response/output side, the (possibly
                # redacted) ingress content is not substituted back into the
                # request body here -- only the Decision is surfaced.
                scope.setdefault("state", {})["agentvanguard_ingress"] = decision

        # The request body was fully consumed by `_read_body` above, so the
        # wrapped app needs a `receive` that replays the buffered messages
        # before falling through to the real `receive` (which by this point
        # has nothing left to give, since `more_body` was already False).
        queue = list(body_messages)

        async def replay_receive() -> Message:
            if queue:
                return queue.pop(0)
            return await receive()

        if not self.check_output:
            # Output checking disabled: call straight through with the
            # original `send`, so responses (including streaming ones) are
            # never buffered.
            await self.app(scope, replay_receive, send)
            return

        await self._call_with_output_check(scope, replay_receive, send)

    async def _call_with_output_check(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Run the wrapped app with a buffering `send`, then authorize the
        complete response body as `action=output` before relaying a single
        (possibly redacted) response to the real `send`.

        Because this buffers the *entire* response -- both the
        `http.response.start` and every `http.response.body` chunk -- before
        any of it is forwarded downstream, nothing is sent to the real
        client until the wrapped app has fully finished responding. This
        makes the middleware unsuitable for streaming responses (e.g.
        Server-Sent Events or chunked/long-poll responses): a streaming
        response would be held in memory until the stream closes (and could
        be unboundedly large), defeating the purpose of streaming and risking
        unbounded memory growth. For streaming endpoints, check output via
        the sidecar (`/v1/check-output`) at the point each chunk is produced
        instead of relying on this middleware.
        """

        buffered: dict[str, Any] = {}

        async def buffering_send(message: Message) -> None:
            # Intercepts both ASGI response message types and accumulates
            # them instead of forwarding to the real `send` -- the start
            # message (status/headers) is captured once, and each body
            # chunk is concatenated onto a single in-memory buffer.
            if message["type"] == "http.response.start":
                buffered["start"] = message
            elif message["type"] == "http.response.body":
                buffered["body"] = buffered.get("body", b"") + message.get("body", b"")

        # Drive the wrapped app to completion against the buffering `send`;
        # nothing reaches the real client until this returns.
        await self.app(scope, receive, buffering_send)

        start_message = buffered.get("start")
        if start_message is None:
            # The wrapped app never sent a response.start message (e.g. it
            # raised without producing any ASGI messages) -- nothing to
            # relay or check.
            return

        status = start_message["status"]
        headers: list[tuple[bytes, bytes]] = list(start_message.get("headers", []))
        response_body: bytes = buffered.get("body", b"")

        if 200 <= status < 300 and response_body:
            # Only successful (2xx) responses with a body are scanned;
            # error responses, redirects, and empty bodies pass through
            # unmodified.
            if len(response_body) > self.max_body_bytes:
                # Fail-closed: an oversized response body cannot be safely
                # inspected, so it is rejected (502) rather than relayed
                # unchecked.
                await _send_json(send, 502, _oversized_payload("response"))
                return
            text = _decode(response_body)
            if text is not None:
                # Binary/non-UTF-8 response bodies are left unchecked, same
                # as on the ingress side.
                decision = self.firewall.authorize(
                    PolicyInput(action=ActionKind.OUTPUT, content=text, arguments={"destination": "plain"})
                )
                if decision.decision == DecisionAction.DENY:
                    # DENY on the output side: the real response is replaced
                    # entirely by a 502 with the decision's reasons/trace_id
                    # -- the original (blocked) response body is discarded
                    # and never reaches the caller.
                    await _send_json(send, 502, _blocked_payload(decision))
                    return
                if decision.redacted_content is not None:
                    # ALLOW_WITH_MODIFICATIONS: the output guard found
                    # something to redact (e.g. a secret/PII match). The
                    # original response body is replaced in-place by the
                    # redacted text and Content-Length is recomputed to
                    # match, so downstream clients see consistent framing.
                    response_body = decision.redacted_content.encode("utf-8")
                    headers = _set_content_length(headers, len(response_body))

        # Finally relay exactly one response (possibly redacted) to the real
        # client, as two ASGI messages: the (possibly already-sent) status/
        # headers, then the full body in a single chunk with more_body=False.
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": response_body, "more_body": False})


async def _read_body(receive: Receive, max_bytes: int) -> tuple[bytes, list[Message], bool]:
    """Drain `receive` until the ASGI request body is fully read (i.e. until
    a message with `more_body=False`), returning the concatenated body
    bytes, the raw list of ASGI messages received (so they can be replayed
    verbatim to the wrapped app afterwards), and whether the body exceeded
    `max_bytes`.

    Note this always reads to the end of the body even after `max_bytes` is
    exceeded (it only sets `truncated=True` and keeps going) -- the caller
    is responsible for rejecting the request when `truncated` is True; this
    function's job is purely to consume and report, not to enforce limits.
    """

    body = b""
    messages: list[Message] = []
    truncated = False

    while True:
        message = await receive()
        messages.append(message)
        body += message.get("body", b"")
        if len(body) > max_bytes:
            truncated = True
        if not message.get("more_body", False):
            break

    return body, messages, truncated


def _decode(data: bytes) -> str | None:
    """Best-effort UTF-8 decode for text inspection; returns `None` (rather
    than raising) for binary/non-UTF-8 payloads, which the caller treats as
    "not inspectable" and passes through unchecked."""

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _blocked_payload(decision: Decision) -> dict[str, Any]:
    """JSON body sent in place of the real request/response when a `Decision`
    is `DENY`, surfacing the engine's decision, reasons, and trace_id to the
    caller for debugging/auditing instead of the blocked content."""

    return {
        "error": "blocked_by_agentvanguard",
        "decision": decision.decision.value,
        "reasons": decision.reasons,
        "trace_id": decision.trace_id,
    }


def _oversized_payload(side: str) -> dict[str, Any]:
    """JSON body sent when a request or response body exceeds
    `max_body_bytes` and is rejected fail-closed rather than being relayed
    uninspected; `side` is `"request"` or `"response"`, used only in the
    human-readable reason string."""

    return {
        "error": "blocked_by_agentvanguard",
        "decision": DecisionAction.DENY.value,
        "reasons": [f"{side} body exceeds max_body_bytes and cannot be inspected (fail-closed)"],
        "trace_id": None,
    }


def _set_content_length(headers: list[tuple[bytes, bytes]], length: int) -> list[tuple[bytes, bytes]]:
    """Return `headers` with any existing `Content-Length` entry replaced by
    `length` -- used after redaction rewrites the response body to a
    different size than the wrapped app originally reported, so downstream
    HTTP clients don't under/over-read the body."""

    updated = [(key, value) for key, value in headers if key.lower() != b"content-length"]
    updated.append((b"content-length", str(length).encode("ascii")))
    return updated


async def _send_json(send: Send, status: int, payload: dict[str, Any]) -> None:
    """Send a complete single-chunk JSON response (`http.response.start` +
    `http.response.body` with `more_body=False`) directly via `send`,
    bypassing the wrapped app entirely -- used for the 403/413/502
    short-circuit responses emitted on DENY or oversized-body rejection."""

    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})
