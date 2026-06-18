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
    """`AgentVanguardClient("http://localhost:8080")`."""

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._client = httpx.Client(base_url=base_url, timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AgentVanguardClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def healthz(self) -> dict[str, str]:
        return self._get("/healthz")

    def readyz(self) -> dict[str, str]:
        return self._get("/readyz")

    def authorize(self, policy_input: PolicyInput) -> Decision:
        return self._post("/v1/authorize", policy_input.model_dump(mode="json", exclude_none=True))

    def check_ingress(
        self,
        content: list[ContentItem] | str,
        **kwargs: Any,
    ) -> Decision:
        return self._post("/v1/check-ingress", _payload(content=content, **kwargs))

    def check_model_request(
        self,
        content: list[ContentItem] | str,
        **kwargs: Any,
    ) -> Decision:
        return self._post("/v1/check-model-request", _payload(content=content, **kwargs))

    def authorize_tool_call(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Decision:
        return self._post("/v1/authorize-tool-call", _payload(tool=tool, arguments=arguments or {}, **kwargs))

    def check_output(
        self,
        content: str,
        destination: str = "plain",
        **kwargs: Any,
    ) -> Decision:
        return self._post("/v1/check-output", _payload(content=content, destination=destination, **kwargs))

    def compile_context(
        self,
        items: list[ContentItem],
        **kwargs: Any,
    ) -> Decision:
        return self._post("/v1/compile-context", _payload(items=items, **kwargs))

    def check_memory_read(
        self,
        content: str,
        source_id: str | None = None,
        **kwargs: Any,
    ) -> Decision:
        return self._post("/v1/check-memory-read", _payload(content=content, source_id=source_id, **kwargs))

    def check_memory_write(
        self,
        content: str,
        source_id: str | None = None,
        **kwargs: Any,
    ) -> Decision:
        return self._post("/v1/check-memory-write", _payload(content=content, source_id=source_id, **kwargs))

    def validate_plan(
        self,
        plan: list[PlanStep | dict[str, Any]],
        **kwargs: Any,
    ) -> ValidatePlanResponse:
        steps = [step.model_dump(mode="json") if isinstance(step, PlanStep) else step for step in plan]
        response = self._client.post("/v1/validate-plan", json=_payload(plan=steps, **kwargs))
        response.raise_for_status()
        return ValidatePlanResponse.model_validate(response.json())

    def _get(self, path: str) -> dict[str, str]:
        response = self._client.get(path)
        response.raise_for_status()
        return response.json()  # type: ignore[no-any-return]

    def _post(self, path: str, json: dict[str, Any]) -> Decision:
        response = self._client.post(path, json=json)
        response.raise_for_status()
        return Decision.model_validate(response.json())


def _payload(**kwargs: Any) -> dict[str, Any]:
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
