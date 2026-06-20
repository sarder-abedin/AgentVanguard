"""`BodySizeLimitMiddleware` — enforces `config.server.max_request_body_bytes`
on every incoming HTTP request to the sidecar.

`uvicorn` has no built-in flag for a maximum request body size, so it has to
be enforced at the ASGI-app level instead. This is plain ASGI (not
`starlette.middleware.base.BaseHTTPMiddleware`) deliberately: `BaseHTTPMiddleware`
buffers the *entire* request body into memory (via `await request.body()`)
before a handler gets a chance to react to its size, which is exactly the
unbounded-memory behavior this middleware exists to prevent. Operating at
the raw ASGI `receive` level instead lets the body be rejected as soon as
the cumulative size crosses the limit, without buffering more of it than
already arrived.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class _PayloadTooLarge(Exception):
    """Raised internally by the wrapped `receive` once the cumulative body
    size exceeds the configured limit; always caught by `__call__` below and
    turned into a `413` response -- never observed by the wrapped app."""


class BodySizeLimitMiddleware:
    """Rejects any HTTP request whose body exceeds `max_body_bytes` with a
    `413 Payload Too Large` response.

    Two layers of defense, since a client is not required to send an
    accurate (or any) `Content-Length` header:

    1. **Fast path**: if `Content-Length` is present and already exceeds the
       limit, reject immediately, before calling the wrapped app at all.
    2. **Streaming guard**: regardless of the declared `Content-Length` (or
       its absence, e.g. chunked transfer encoding), the `receive` callable
       passed down to the wrapped app is wrapped to track the cumulative
       size of every `http.request` message's body as it arrives. Once the
       running total exceeds the limit, the wrapped `receive` raises
       `_PayloadTooLarge`, which this middleware catches and turns into the
       same `413` response -- the wrapped app (FastAPI/Starlette routing,
       pydantic validation, etc.) never sees more than `max_body_bytes` of
       attacker-controlled body.
    """

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = _header(scope, b"content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = None
            if declared_size is not None and declared_size > self.max_body_bytes:
                await _send_413(send)
                return

        seen = 0

        async def limited_receive() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_body_bytes:
                    raise _PayloadTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _PayloadTooLarge:
            await _send_413(send)


def _header(scope: Scope, name: bytes) -> bytes | None:
    """Look up a single ASGI request header by (lowercase) byte name,
    e.g. `_header(scope, b"content-length")`. Returns `None` if absent."""

    for key, value in scope.get("headers") or []:
        if key.lower() == name:
            return value  # type: ignore[no-any-return]
    return None


async def _send_413(send: Send) -> None:
    """Emit a minimal `413 Payload Too Large` JSON response and nothing
    else -- used both by the `Content-Length` fast path (before any
    response has started) and by the streaming guard (caught right after
    `_PayloadTooLarge` is raised, also before any response has started,
    since FastAPI/Starlette only start sending a response after the body
    has been fully read)."""

    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": b'{"detail":"request body exceeds max_request_body_bytes"}'})
