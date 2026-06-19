"""`AgentVanguardClient` — thin `httpx`-based client for the sidecar/API
service started by `agentvanguard serve` (requires the `server` extra,
which also pulls in `httpx`).

Every method mirrors a route in `agentvanguard.server.routes` and returns a
`Decision`. Non-Python callers can hit the same JSON endpoints directly.
"""

from __future__ import annotations

from typing import Any

import httpx

from agentvanguard.core.models import ContentItem, Decision, PolicyInput
from agentvanguard.server.schemas import PlanStep, ValidatePlanResponse


class AgentVanguardClient:
    """`AgentVanguardClient("http://localhost:8080")`.

    One method per sidecar route; each builds a small JSON payload (dropping
    `None`-valued fields and serializing pydantic models via `_payload`),
    POSTs/GETs it with the underlying `httpx.Client`, and parses the
    response back into a `Decision` (or `ValidatePlanResponse`,
    or a plain dict for the health endpoints). Usable as a context manager
    (`with AgentVanguardClient(...) as client:`) to ensure the underlying
    `httpx.Client` is closed.
    """

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        # All requests are relative to `base_url` (e.g. the host:port the
        # sidecar's `agentvanguard serve` is listening on); `timeout` bounds
        # every HTTP call made through this client.
        self._client = httpx.Client(base_url=base_url, timeout=timeout)

    def close(self) -> None:
        """Close the underlying `httpx.Client` and release its connection
        pool. Safe to call even if the client is used as a context manager
        (in which case `__exit__` calls this automatically)."""

        self._client.close()

    def __enter__(self) -> "AgentVanguardClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def healthz(self) -> dict[str, str]:
        """`GET /healthz` -- process liveness; returns `{"status": "ok"}` if
        the sidecar process is up. Does not call `Engine.authorize()`."""

        return self._get("/healthz")

    def readyz(self) -> dict[str, str]:
        """`GET /readyz` -- readiness (config loaded, engine initialized,
        audit sink writable); raises via `httpx`'s `raise_for_status()` if
        the sidecar responds 503 (not ready). Does not call
        `Engine.authorize()`."""

        return self._get("/readyz")

    def authorize(self, policy_input: PolicyInput) -> Decision:
        """`POST /v1/authorize` with the full `PolicyInput` serialized as
        JSON (`action` may be any `ActionKind`). Mirrors
        `routes.authorize`, the generic, non-convenience endpoint."""

        return self._post("/v1/authorize", policy_input.model_dump(mode="json", exclude_none=True))

    def check_ingress(
        self,
        content: list[ContentItem] | str,
        **kwargs: Any,
    ) -> Decision:
        """`POST /v1/check-ingress` (`action=ingress`). Mirrors
        `routes.check_ingress`; `**kwargs` may include `actor`, `agent`,
        `workflow`, `session_id` (any `IngressRequest` field besides
        `content`)."""

        return self._post("/v1/check-ingress", _payload(content=content, **kwargs))

    def check_model_request(
        self,
        content: list[ContentItem] | str,
        **kwargs: Any,
    ) -> Decision:
        """`POST /v1/check-model-request` (`action=model_request`). Mirrors
        `routes.check_model_request`; `**kwargs` may include `actor`,
        `agent`, `workflow`, `session_id`."""

        return self._post("/v1/check-model-request", _payload(content=content, **kwargs))

    def authorize_tool_call(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Decision:
        """`POST /v1/authorize-tool-call` (`action=tool_call`). Mirrors
        `routes.authorize_tool_call`; `**kwargs` may include `actor`,
        `agent`, `workflow`, `content`, `session_id`."""

        return self._post("/v1/authorize-tool-call", _payload(tool=tool, arguments=arguments or {}, **kwargs))

    def check_output(
        self,
        content: str,
        destination: str = "plain",
        **kwargs: Any,
    ) -> Decision:
        """`POST /v1/check-output` (`action=output`). Mirrors
        `routes.check_output`; the returned `Decision.redacted_content` is
        populated when the output guard's DLP finds something to redact.
        `**kwargs` may include `actor`, `agent`, `workflow`, `session_id`."""

        return self._post("/v1/check-output", _payload(content=content, destination=destination, **kwargs))

    def compile_context(
        self,
        items: list[ContentItem],
        **kwargs: Any,
    ) -> Decision:
        """`POST /v1/compile-context` (`action=ingress` over a list of
        pre-tagged `ContentItem`s). Mirrors `routes.compile_context`;
        `**kwargs` may include `actor`, `agent`, `workflow`, `session_id`."""

        return self._post("/v1/compile-context", _payload(items=items, **kwargs))

    def check_memory_read(
        self,
        content: str,
        source_id: str | None = None,
        **kwargs: Any,
    ) -> Decision:
        """`POST /v1/check-memory-read` (`action=ingress`, content always
        tagged `retrieved_doc` provenance server-side). Mirrors
        `routes.check_memory_read`; `**kwargs` may include `actor`, `agent`,
        `workflow`, `session_id`."""

        return self._post("/v1/check-memory-read", _payload(content=content, source_id=source_id, **kwargs))

    def check_memory_write(
        self,
        content: str,
        source_id: str | None = None,
        **kwargs: Any,
    ) -> Decision:
        """`POST /v1/check-memory-write` (`action=output`, DLP over content
        about to be persisted to memory/vector storage). Mirrors
        `routes.check_memory_write`; `**kwargs` may include `actor`, `agent`,
        `workflow`, `session_id`."""

        return self._post("/v1/check-memory-write", _payload(content=content, source_id=source_id, **kwargs))

    def validate_plan(
        self,
        plan: list[PlanStep | dict[str, Any]],
        **kwargs: Any,
    ) -> ValidatePlanResponse:
        """`POST /v1/validate-plan` (`action=tool_call` per step). Mirrors
        `routes.validate_plan`; `plan` entries may be `PlanStep` instances or
        plain dicts with the same shape (`tool`, `arguments`, `content`).
        Unlike the other methods, the response is a `ValidatePlanResponse`
        (an `overall` worst-action-wins decision plus one `Decision` per
        step), not a single `Decision`, so this bypasses `_post` and parses
        the response body directly. `**kwargs` may include `actor`, `agent`,
        `workflow`, `session_id`."""

        steps = [step.model_dump(mode="json") if isinstance(step, PlanStep) else step for step in plan]
        response = self._client.post("/v1/validate-plan", json=_payload(plan=steps, **kwargs))
        response.raise_for_status()
        return ValidatePlanResponse.model_validate(response.json())

    def _get(self, path: str) -> dict[str, str]:
        """Shared GET helper for the two health endpoints: issues the
        request, raises on a non-2xx status via `httpx`, and returns the
        decoded JSON body as a plain dict."""

        response = self._client.get(path)
        response.raise_for_status()
        return response.json()  # type: ignore[no-any-return]

    def _post(self, path: str, json: dict[str, Any]) -> Decision:
        """Shared POST helper for every `Decision`-returning route: issues
        the request, raises on a non-2xx status via `httpx`, and validates
        the JSON response body into a `Decision`."""

        response = self._client.post(path, json=json)
        response.raise_for_status()
        return Decision.model_validate(response.json())


def _payload(**kwargs: Any) -> dict[str, Any]:
    """Build a JSON-ready request body dict from keyword arguments.

    Drops any keyword whose value is `None` (so optional fields are omitted
    entirely rather than sent as JSON `null`, matching what the server-side
    pydantic request models expect for unset optional fields), and
    recursively serializes pydantic models (`ContentItem`, `Actor`,
    `AgentIdentity`, etc., detected via `hasattr(value, "model_dump")`) --
    including ones nested inside lists -- via `model_dump(mode="json")`.
    Plain JSON-serializable values (str, dict, etc.) are passed through
    unchanged.
    """

    payload: dict[str, Any] = {}
    for key, value in kwargs.items():
        if value is None:
            continue
        if isinstance(value, list):
            payload[key] = [item.model_dump(mode="json") if isinstance(item, ContentItem) else item for item in value]
        elif hasattr(value, "model_dump"):
            payload[key] = value.model_dump(mode="json")
        else:
            payload[key] = value
    return payload
