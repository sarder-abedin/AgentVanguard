"""Sidecar HTTP routes.

Every route either accepts a `PolicyInput` directly (`/v1/authorize`) or
builds one from an action-specific convenience request model
(`server/schemas.py`) and calls `AgentVanguard.authorize()` — the same
`Engine.authorize()` used by the SDK and tool-broker. No policy logic lives
here.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response

from agentvanguard.core.enums import ActionKind, ProvenanceLabel
from agentvanguard.core.models import ContentItem, Decision, PolicyInput
from agentvanguard.firewall import AgentVanguard
from agentvanguard.observability import metrics
from agentvanguard.policy.risk import worst_action
from agentvanguard.server.deps import get_firewall
from agentvanguard.server.schemas import (
    CompileContextRequest,
    IngressRequest,
    MemoryReadRequest,
    MemoryWriteRequest,
    ModelRequestRequest,
    OutputRequest,
    ToolCallRequest,
    ValidatePlanRequest,
    ValidatePlanResponse,
)

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Process liveness — does not touch config or the audit sink."""

    return {"status": "ok"}


@router.get("/readyz")
def readyz(firewall: AgentVanguard = Depends(get_firewall)) -> dict[str, str]:
    """Readiness — config loaded, engine initialized, audit sink writable."""

    for sink in firewall.engine.audit.sinks:
        path = getattr(sink, "path", None)
        if path is None:
            continue
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            probe = path.parent / ".agentvanguard_write_test"
            probe.write_text("")
            probe.unlink()
        except OSError as exc:
            raise HTTPException(status_code=503, detail=f"audit sink not writable: {exc}") from exc

    return {"status": "ready"}


@router.post("/v1/authorize", response_model=Decision)
def authorize(policy_input: PolicyInput, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """Generic endpoint: body is a full `PolicyInput`, returns a `Decision`."""

    return firewall.authorize(policy_input)


@router.post("/v1/check-ingress", response_model=Decision)
def check_ingress(req: IngressRequest, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """`action=ingress` convenience wrapper."""

    return firewall.authorize(PolicyInput(action=ActionKind.INGRESS, **req.model_dump()))


@router.post("/v1/check-model-request", response_model=Decision)
def check_model_request(
    req: ModelRequestRequest, firewall: AgentVanguard = Depends(get_firewall)
) -> Decision:
    """`action=model_request` convenience wrapper."""

    return firewall.authorize(PolicyInput(action=ActionKind.MODEL_REQUEST, **req.model_dump()))


@router.post("/v1/authorize-tool-call", response_model=Decision)
def authorize_tool_call(
    req: ToolCallRequest, firewall: AgentVanguard = Depends(get_firewall)
) -> Decision:
    """`action=tool_call` convenience wrapper."""

    return firewall.authorize(PolicyInput(action=ActionKind.TOOL_CALL, **req.model_dump()))


@router.post("/v1/check-output", response_model=Decision)
def check_output(req: OutputRequest, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """`action=output` convenience wrapper."""

    data = req.model_dump(exclude={"destination"})
    return firewall.authorize(
        PolicyInput(action=ActionKind.OUTPUT, arguments={"destination": req.destination}, **data)
    )


@router.post("/v1/compile-context", response_model=Decision)
def compile_context(req: CompileContextRequest, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """`action=ingress` wrapper over a list of RAG-retrieved `ContentItem`s,
    each carrying its own `provenance`."""

    data = req.model_dump(exclude={"items"})
    return firewall.authorize(PolicyInput(action=ActionKind.INGRESS, content=req.items, **data))


@router.post("/v1/check-memory-read", response_model=Decision)
def check_memory_read(req: MemoryReadRequest, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """`action=ingress` wrapper that always tags `content` as
    `retrieved_doc` provenance, regardless of the original source -- this is
    where memory-poisoning content is caught by the input guard's injection
    detector."""

    data = req.model_dump(exclude={"content", "source_id"})
    content = [ContentItem(text=req.content, provenance=ProvenanceLabel.RETRIEVED_DOC, source_id=req.source_id)]
    return firewall.authorize(PolicyInput(action=ActionKind.INGRESS, content=content, **data))


@router.post("/v1/check-memory-write", response_model=Decision)
def check_memory_write(req: MemoryWriteRequest, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """`action=output` wrapper -- runs the output guard (DLP) over content
    about to be persisted to a memory/vector store."""

    data = req.model_dump(exclude={"content", "source_id"})
    content = [ContentItem(text=req.content, provenance=ProvenanceLabel.ASSISTANT, source_id=req.source_id)]
    return firewall.authorize(
        PolicyInput(action=ActionKind.OUTPUT, content=content, arguments={"destination": "plain"}, **data)
    )


@router.post("/v1/validate-plan", response_model=ValidatePlanResponse)
def validate_plan(req: ValidatePlanRequest, firewall: AgentVanguard = Depends(get_firewall)) -> ValidatePlanResponse:
    """Validate a multi-step tool-call plan *before* executing any of it.

    Each step is authorized as `action=tool_call` (in order, so session
    counters/repetition tracking accumulate across steps); `overall` is the
    worst-action-wins `Decision.decision` across all steps.
    """

    shared = req.model_dump(exclude={"plan"})
    steps = [
        firewall.authorize(
            PolicyInput(action=ActionKind.TOOL_CALL, tool=step.tool, arguments=step.arguments, content=step.content, **shared)
        )
        for step in req.plan
    ]
    return ValidatePlanResponse(overall=worst_action(step.decision for step in steps), steps=steps)


@router.get("/metrics")
def metrics_endpoint() -> Response:
    """Prometheus exposition format, or an empty body if the `metrics` extra
    isn't installed."""

    return Response(content=metrics.render_latest(), media_type=metrics.CONTENT_TYPE_LATEST)
