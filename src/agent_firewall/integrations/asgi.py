"""`AgentFirewallMiddleware` -- pure ASGI middleware that mediates an
existing app's HTTP traffic through `Engine.authorize()`.

For each HTTP request/response cycle:

1. Buffers the request body (up to `max_body_bytes`) and, if it decodes as
   UTF-8 text, runs `action=ingress` over it. A `DENY` short-circuits with a
   `403` JSON response (fail-closed); otherwise the `Decision` is attached to
   `scope["state"]["agent_firewall_ingress"]` (readable as
   `request.state.agent_firewall_ingress` in Starlette/FastAPI) and the
   request is replayed to the wrapped app unchanged.
2. Buffers the response body and, for 2xx responses that decode as UTF-8
   text, runs `action=output` over it. A `DENY` short-circuits with a `502`;
   `ALLOW_WITH_MODIFICATIONS` rewrites the body (and `Content-Length`) to the
   redacted text.

Both checks are best-effort and skip oversized or non-UTF-8 bodies. Because
the whole response body is buffered before any of it is sent downstream,
this middleware is **not** suitable for streaming responses (e.g. SSE) --
use the sidecar (`/v1/check-output`) for those instead.

    from agent_firewall import AgentFirewall
    from agent_firewall.integrations.asgi import AgentFirewallMiddleware

    firewall = AgentFirewall.from_config("agent_firewall.yaml")
    app = AgentFirewallMiddleware(app, firewall)
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from agent_firewall.core.enums import ActionKind, DecisionAction
from agent_firewall.core.models import Decision, PolicyInput
from agent_firewall.firewall import AgentFirewall

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


class AgentFirewallMiddleware:
    """ASGI middleware mediating ingress/egress through `Engine.authorize()`.

    Wrap any ASGI 3 application (FastAPI, Starlette, raw ASGI):

        app = AgentFirewallMiddleware(app, firewall)
    """

    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        firewall: AgentFirewall,
        *,
        max_body_bytes: int = 1_000_000,
        check_ingress: bool = True,
        check_output: bool = True,
    ) -> None:
        self.app = app
        self.firewall = firewall
        self.max_body_bytes = max_body_bytes
        self.check_ingress = check_ingress
        self.check_output = check_output

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        body, body_messages, truncated = await _read_body(receive, self.max_body_bytes)

        if self.check_ingress and body and not truncated:
            text = _decode(body)
            if text is not None:
                decision = self.firewall.authorize(PolicyInput(action=ActionKind.INGRESS, content=text))
                if decision.decision == DecisionAction.DENY:
                    await _send_json(send, 403, _blocked_payload(decision))
                    return
                scope.setdefault("state", {})["agent_firewall_ingress"] = decision

        queue = list(body_messages)

        async def replay_receive() -> Message:
            if queue:
                return queue.pop(0)
            return await receive()

        if not self.check_output:
            await self.app(scope, replay_receive, send)
            return

        await self._call_with_output_check(scope, replay_receive, send)

    async def _call_with_output_check(self, scope: Scope, receive: Receive, send: Send) -> None:
        buffered: dict[str, Any] = {}

        async def buffering_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                buffered["start"] = message
            elif message["type"] == "http.response.body":
                buffered["body"] = buffered.get("body", b"") + message.get("body", b"")

        await self.app(scope, receive, buffering_send)

        start_message = buffered.get("start")
        if start_message is None:
            return

        status = start_message["status"]
        headers: list[tuple[bytes, bytes]] = list(start_message.get("headers", []))
        response_body: bytes = buffered.get("body", b"")

        if 200 <= status < 300 and response_body and len(response_body) <= self.max_body_bytes:
            text = _decode(response_body)
            if text is not None:
                decision = self.firewall.authorize(
                    PolicyInput(action=ActionKind.OUTPUT, content=text, arguments={"destination": "plain"})
                )
                if decision.decision == DecisionAction.DENY:
                    await _send_json(send, 502, _blocked_payload(decision))
                    return
                if decision.redacted_content is not None:
                    response_body = decision.redacted_content.encode("utf-8")
                    headers = _set_content_length(headers, len(response_body))

        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": response_body, "more_body": False})


async def _read_body(receive: Receive, max_bytes: int) -> tuple[bytes, list[Message], bool]:
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
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _blocked_payload(decision: Decision) -> dict[str, Any]:
    return {
        "error": "blocked_by_agent_firewall",
        "decision": decision.decision.value,
        "reasons": decision.reasons,
        "trace_id": decision.trace_id,
    }


def _set_content_length(headers: list[tuple[bytes, bytes]], length: int) -> list[tuple[bytes, bytes]]:
    updated = [(key, value) for key, value in headers if key.lower() != b"content-length"]
    updated.append((b"content-length", str(length).encode("ascii")))
    return updated


async def _send_json(send: Send, status: int, payload: dict[str, Any]) -> None:
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
