"""Sidecar HTTP routes.

Every route either accepts a `PolicyInput` directly (`/v1/authorize`) or
builds one from an action-specific convenience request model
(`server/schemas.py`) and calls `AgentFirewall.authorize()` — the same
`Engine.authorize()` used by the SDK and tool-broker. No policy logic lives
here.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from agent_firewall.core.enums import ActionKind
from agent_firewall.core.models import Decision, PolicyInput
from agent_firewall.firewall import AgentFirewall
from agent_firewall.server.deps import get_firewall
from agent_firewall.server.schemas import (
    IngressRequest,
    ModelRequestRequest,
    OutputRequest,
    ToolCallRequest,
)

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Process liveness — does not touch config or the audit sink."""

    return {"status": "ok"}


@router.get("/readyz")
def readyz(firewall: AgentFirewall = Depends(get_firewall)) -> dict[str, str]:
    """Readiness — config loaded, engine initialized, audit sink writable."""

    for sink in firewall.engine.audit.sinks:
        path = getattr(sink, "path", None)
        if path is None:
            continue
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            probe = path.parent / ".agent_firewall_write_test"
            probe.write_text("")
            probe.unlink()
        except OSError as exc:
            raise HTTPException(status_code=503, detail=f"audit sink not writable: {exc}") from exc

    return {"status": "ready"}


@router.post("/v1/authorize", response_model=Decision)
def authorize(policy_input: PolicyInput, firewall: AgentFirewall = Depends(get_firewall)) -> Decision:
    """Generic endpoint: body is a full `PolicyInput`, returns a `Decision`."""

    return firewall.authorize(policy_input)


@router.post("/v1/check-ingress", response_model=Decision)
def check_ingress(req: IngressRequest, firewall: AgentFirewall = Depends(get_firewall)) -> Decision:
    """`action=ingress` convenience wrapper."""

    return firewall.authorize(PolicyInput(action=ActionKind.INGRESS, **req.model_dump()))


@router.post("/v1/check-model-request", response_model=Decision)
def check_model_request(
    req: ModelRequestRequest, firewall: AgentFirewall = Depends(get_firewall)
) -> Decision:
    """`action=model_request` convenience wrapper."""

    return firewall.authorize(PolicyInput(action=ActionKind.MODEL_REQUEST, **req.model_dump()))


@router.post("/v1/authorize-tool-call", response_model=Decision)
def authorize_tool_call(
    req: ToolCallRequest, firewall: AgentFirewall = Depends(get_firewall)
) -> Decision:
    """`action=tool_call` convenience wrapper."""

    return firewall.authorize(PolicyInput(action=ActionKind.TOOL_CALL, **req.model_dump()))


@router.post("/v1/check-output", response_model=Decision)
def check_output(req: OutputRequest, firewall: AgentFirewall = Depends(get_firewall)) -> Decision:
    """`action=output` convenience wrapper."""

    data = req.model_dump(exclude={"destination"})
    return firewall.authorize(
        PolicyInput(action=ActionKind.OUTPUT, arguments={"destination": req.destination}, **data)
    )
