"""Sidecar HTTP routes.

Every route either accepts a `PolicyInput` directly (`/v1/authorize`) or
builds one from an action-specific convenience request model
(`server/schemas.py`) and calls `AgentVanguard.authorize()` — the same
`Engine.authorize()` used by the SDK and tool-broker. No policy logic lives
here.

Every route below except `/healthz`/`/readyz` carries `dependencies=[Depends
(require_api_key)]`, gated by `config.server.api_keys` (see
`server/deps.py`) -- `/healthz`/`/readyz` are deliberately left
unauthenticated since orchestrator liveness/readiness probes typically
cannot attach a secret header.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from agentvanguard.core.enums import ActionKind, ProvenanceLabel
from agentvanguard.core.models import ContentItem, Decision, PolicyInput
from agentvanguard.firewall import AgentVanguard
from agentvanguard.observability import metrics
from agentvanguard.policy.risk import worst_action
from agentvanguard.server.deps import get_firewall, require_api_key
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


def _data(req: BaseModel, exclude: set[str] | None = None) -> dict:
    """`req.model_dump()`, always dropping `session_state`.

    Over the network-facing sidecar, an unauthenticated caller must not be
    able to forge or reset another `session_id`'s runtime-limit/repetition
    counters by supplying a fabricated `SessionState` in the request body --
    session state is always resolved server-side via the `SessionStore`.
    """

    # `exclude` lets each call site additionally drop fields it needs to
    # handle itself (e.g. `destination`, `items`, `content`/`source_id`,
    # `plan`) before re-assembling them into the `PolicyInput` it builds, on
    # top of the `session_state` field this helper always strips.
    return req.model_dump(exclude={"session_state"} | (exclude or set()))


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Process liveness — does not touch config or the audit sink.

    No `ActionKind` involved: this endpoint never builds a `PolicyInput` or
    calls `Engine.authorize()`. It only proves the process is up and able to
    answer HTTP requests at all, for container/orchestrator liveness probes.
    """

    return {"status": "ok"}


@router.get("/readyz")
def readyz(firewall: AgentVanguard = Depends(get_firewall)) -> dict[str, str]:
    """Readiness — config loaded, engine initialized, audit sink writable.

    No `ActionKind` involved: like `healthz`, this never calls
    `Engine.authorize()`. It exercises a stronger check than `healthz` --
    that the `AgentVanguard`/`Engine` were constructed successfully (via the
    `get_firewall` dependency) and that every file-backed audit sink's
    directory exists and is writable, by probing a throwaway file in it.
    Intended for orchestrator readiness probes (e.g. to gate traffic until
    the audit pipeline can actually persist events).
    """

    for sink in firewall.engine.audit.sinks:
        path = getattr(sink, "path", None)
        if path is None:
            # Sinks without a `path` attribute (e.g. HTTP-batch sinks) have
            # nothing filesystem-related to probe here.
            continue
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            probe = path.parent / ".agentvanguard_write_test"
            probe.write_text("")
            probe.unlink()
        except OSError as exc:
            # Fail-closed: an unwritable audit sink means decisions could be
            # made without being recorded, so report not-ready (503) rather
            # than ready.
            raise HTTPException(status_code=503, detail=f"audit sink not writable: {exc}") from exc

    return {"status": "ready"}


@router.post("/v1/authorize", response_model=Decision, dependencies=[Depends(require_api_key)])
def authorize(policy_input: PolicyInput, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """Generic endpoint: body is a full `PolicyInput`, returns a `Decision`.

    Unlike the convenience endpoints below, the caller supplies `action`
    directly inside the request body (it can be any `ActionKind` --
    `ingress`, `model_request`, `tool_call`, or `output`), so this single
    route covers all four trust boundaries. Used when a caller already has a
    fully-formed `PolicyInput` (e.g. another internal service, or a client
    that wants access to fields the convenience models don't expose).

    `session_state` is never honored from the request body here -- over the
    network-facing sidecar, an unauthenticated caller could otherwise forge
    or reset another `session_id`'s runtime-limit/repetition counters by
    supplying a fabricated `SessionState`. Session state is always resolved
    server-side from the `SessionStore`, keyed by `session_id`.
    """

    # Strip any caller-supplied session_state before it ever reaches the
    # engine; `Engine.authorize` resolves the real SessionState itself via
    # the configured SessionStore, keyed by policy_input.session_id.
    policy_input = policy_input.model_copy(update={"session_state": None})
    return firewall.authorize(policy_input)


@router.post("/v1/check-ingress", response_model=Decision, dependencies=[Depends(require_api_key)])
def check_ingress(req: IngressRequest, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """`action=ingress` convenience wrapper.

    Maps to `ActionKind.INGRESS`: checks untrusted input (user message,
    retrieved document, etc.) before it reaches the model -- this is where
    the input guard's prompt-injection/PII detectors run. Builds a
    `PolicyInput` from `IngressRequest`'s fields (via `_data`, which always
    drops any caller-supplied `session_state`) and delegates to
    `Engine.authorize()`.
    """

    return firewall.authorize(PolicyInput(action=ActionKind.INGRESS, **_data(req)))


@router.post("/v1/check-model-request", response_model=Decision, dependencies=[Depends(require_api_key)])
def check_model_request(
    req: ModelRequestRequest, firewall: AgentVanguard = Depends(get_firewall)
) -> Decision:
    """`action=model_request` convenience wrapper.

    Maps to `ActionKind.MODEL_REQUEST`: checks the fully-assembled prompt
    about to be sent to the LLM (after context/RAG assembly), as opposed to
    `check_ingress` which checks individual input/content pieces before
    assembly. Builds a `PolicyInput` from `ModelRequestRequest`'s fields and
    delegates to `Engine.authorize()`.
    """

    return firewall.authorize(PolicyInput(action=ActionKind.MODEL_REQUEST, **_data(req)))


@router.post("/v1/authorize-tool-call", response_model=Decision, dependencies=[Depends(require_api_key)])
def authorize_tool_call(
    req: ToolCallRequest, firewall: AgentVanguard = Depends(get_firewall)
) -> Decision:
    """`action=tool_call` convenience wrapper.

    Maps to `ActionKind.TOOL_CALL`: checks a single proposed tool/action
    invocation (schema validation, SSRF/path-traversal/egress checks,
    credential scanning -- see `guards/tool_guard.py`) before it executes.
    Builds a `PolicyInput` from `ToolCallRequest`'s fields (`tool`,
    `arguments`, etc.) and delegates to `Engine.authorize()`.
    """

    return firewall.authorize(PolicyInput(action=ActionKind.TOOL_CALL, **_data(req)))


@router.post("/v1/check-output", response_model=Decision, dependencies=[Depends(require_api_key)])
def check_output(req: OutputRequest, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """`action=output` convenience wrapper.

    Maps to `ActionKind.OUTPUT`: checks content about to leave the system
    towards `destination` (e.g. "plain" text shown to a user) -- this is
    where the output guard's DLP/redaction runs, populating
    `Decision.redacted_content` when secrets/PII are found.
    """

    # `destination` is pulled out of the dumped dict and passed explicitly
    # via `arguments`, since `PolicyInput` doesn't have a top-level
    # `destination` field of its own -- it's carried inside `arguments`.
    data = _data(req, exclude={"destination"})
    return firewall.authorize(
        PolicyInput(action=ActionKind.OUTPUT, arguments={"destination": req.destination}, **data)
    )


@router.post("/v1/compile-context", response_model=Decision, dependencies=[Depends(require_api_key)])
def compile_context(req: CompileContextRequest, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """`action=ingress` wrapper over a list of RAG-retrieved `ContentItem`s,
    each carrying its own `provenance`.

    Maps to `ActionKind.INGRESS`, like `check_ingress`, but takes a list of
    pre-tagged `ContentItem`s (`req.items`) instead of a single content
    blob/string -- used when assembling a RAG context window out of several
    retrieved chunks that may originate from different sources/trust levels.
    """

    data = _data(req, exclude={"items"})
    return firewall.authorize(PolicyInput(action=ActionKind.INGRESS, content=req.items, **data))


@router.post("/v1/check-memory-read", response_model=Decision, dependencies=[Depends(require_api_key)])
def check_memory_read(req: MemoryReadRequest, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """`action=ingress` wrapper that always tags `content` as
    `retrieved_doc` provenance, regardless of the original source -- this is
    where memory-poisoning content is caught by the input guard's injection
    detector.

    Maps to `ActionKind.INGRESS`. Unlike `check_ingress`/`compile_context`,
    the caller cannot choose the provenance label here: content read back
    from a memory/vector store is always wrapped in a single `ContentItem`
    with `provenance=ProvenanceLabel.RETRIEVED_DOC`, since previously-stored
    content (potentially written by an untrusted prior turn) must always be
    re-screened as if newly retrieved.
    """

    data = _data(req, exclude={"content", "source_id"})
    content = [ContentItem(text=req.content, provenance=ProvenanceLabel.RETRIEVED_DOC, source_id=req.source_id)]
    return firewall.authorize(PolicyInput(action=ActionKind.INGRESS, content=content, **data))


@router.post("/v1/check-memory-write", response_model=Decision, dependencies=[Depends(require_api_key)])
def check_memory_write(req: MemoryWriteRequest, firewall: AgentVanguard = Depends(get_firewall)) -> Decision:
    """`action=output` wrapper -- runs the output guard (DLP) over content
    about to be persisted to a memory/vector store.

    Maps to `ActionKind.OUTPUT`. Wraps `req.content` in a `ContentItem` with
    `provenance=ProvenanceLabel.ASSISTANT` (the content originates from the
    agent/assistant about to write it) and `destination="plain"`, so the same
    DLP/redaction path as `check_output` runs before the write is allowed
    through.
    """

    data = _data(req, exclude={"content", "source_id"})
    content = [ContentItem(text=req.content, provenance=ProvenanceLabel.ASSISTANT, source_id=req.source_id)]
    return firewall.authorize(
        PolicyInput(action=ActionKind.OUTPUT, content=content, arguments={"destination": "plain"}, **data)
    )


@router.post("/v1/validate-plan", response_model=ValidatePlanResponse, dependencies=[Depends(require_api_key)])
def validate_plan(req: ValidatePlanRequest, firewall: AgentVanguard = Depends(get_firewall)) -> ValidatePlanResponse:
    """Validate a multi-step tool-call plan *before* executing any of it.

    Each step is authorized as `action=tool_call` (so this maps to
    `ActionKind.TOOL_CALL`, called once per `PlanStep` in `req.plan`, in
    order so session counters/repetition tracking accumulate across steps as
    they would if the steps were actually executed one-by-one); `overall` is
    the worst-action-wins `Decision.decision` across all steps. Lets a caller
    check an entire planned sequence of tool calls up front (e.g. before an
    agent commits to executing a multi-step plan) rather than discovering a
    `DENY` partway through execution.
    """

    shared = _data(req, exclude={"plan"})
    steps = [
        firewall.authorize(
            PolicyInput(action=ActionKind.TOOL_CALL, tool=step.tool, arguments=step.arguments, content=step.content, **shared)
        )
        for step in req.plan
    ]
    return ValidatePlanResponse(overall=worst_action(step.decision for step in steps), steps=steps)


@router.get("/metrics", dependencies=[Depends(require_api_key)])
def metrics_endpoint() -> Response:
    """Prometheus exposition format, or an empty body if the `metrics` extra
    isn't installed.

    No `ActionKind` involved: this endpoint never builds a `PolicyInput` or
    calls `Engine.authorize()`. It exposes the process's accumulated
    Prometheus counters/histograms (e.g. decisions by action/result) for
    scraping by a Prometheus server, via `observability.metrics`.
    """

    return Response(content=metrics.render_latest(), media_type=metrics.CONTENT_TYPE_LATEST)
