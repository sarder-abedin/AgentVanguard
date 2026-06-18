# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

`agentvanguard` (package `agentvanguard`, src-layout under `src/`) is a
workflow-agnostic firewall for LLM-based agentic systems. It mediates three
trust boundaries — input/context (ingress), tool/action calls, and output —
plus session-level runtime limits. See `docs/architecture.md` for the full
design (threat model, components, decision table) and `README.md` for usage.

## Setup & common commands

```bash
pip install -e ".[dev,server,metrics,otel,redis]"   # full dev install

pytest -q                      # run the full test suite
ruff check src/ tests/         # lint
mypy src/                       # type-check

agentvanguard init             # write agentvanguard.yaml
agentvanguard validate-config
agentvanguard doctor
agentvanguard serve --config agentvanguard.yaml --port 8080   # requires [server] extra
```

There is no separate lint/format config beyond `pyproject.toml` defaults —
keep `ruff` and `mypy` clean before committing.

## Architecture invariant

**`agentvanguard.engine.Engine` is the single shared, synchronous,
in-memory policy core.** Every integration surface — SDK (`firewall.py`),
tool broker, ASGI middleware (`integrations/asgi.py`), and the sidecar HTTP
routes (`server/routes.py`) — builds a `PolicyInput` and calls
`Engine.authorize()`. Never re-implement policy/decision logic in an
integration surface; add it to `policy/`, `guards/`, or `engine.py` instead.

`Engine.authorize()` flow: resolve `SessionState` -> dispatch to the guard(s)
for `policy_input.action` (`ingress`/`model_request`/`tool_call`/`output`) ->
`PolicyEvaluator.evaluate()` produces `Verdict[]` -> aggregate to one
`Decision` via worst-action-wins (`DENY` > `REQUIRE_USER_CONFIRMATION` >
`ALLOW_WITH_MODIFICATIONS` > `ALLOW`) -> consult `ApprovalProvider` if
`REQUIRE_USER_CONFIRMATION` -> update session state -> write `AuditEvent`(s).

Fail-closed by default: unknown tools, unknown workflows, and bundle-fetch
failures (depending on `fail_mode`) deny or restrict rather than allow.

## Package layout (`src/agentvanguard/`)

- `core/` — enums, pydantic models (`PolicyInput`, `Verdict`, `Decision`,
  `ToolManifest`, etc.), errors.
- `config/` — YAML schema (`schema.py`), loader, built-in defaults.
- `detectors/` — heuristic/regex detectors: prompt injection, PII, secrets,
  exfiltration patterns. `registry.py` builds the active set from config.
- `policy/` — `matcher.py` (match-dict rule evaluation), `risk.py` (scoring +
  `Verdict` aggregation), `evaluator.py`.
- `guards/` — `input_guard`, `tool_guard` (schema/SSRF/path-traversal/egress/
  credential-scan), `output_guard` (DLP/redaction), `session_guard` (runtime
  limits, repetition detection).
- `approval/` — `ApprovalProvider` protocol; `auto_deny` (default, fail-closed)
  and `cli_prompt`.
- `audit/` — `AuditLogger` + `AuditEvent` + sinks (`jsonl_file`, `http_batch`).
- `session/` — `SessionStore` protocol, in-memory + Redis implementations,
  `factory.py` to select backend from config.
- `control_plane/` — `PolicyBundleSource` protocol + `HttpPolicyBundleSource`
  for fetching config bundles from a central policy server.
- `integrations/` — `AgentVanguardMiddleware` (ASGI) + FastAPI re-export.
- `observability/` — structured logging, OpenTelemetry tracing, Prometheus
  metrics (`/metrics`).
- `server/` — FastAPI sidecar app (`app.py`, `routes.py`, `schemas.py`).
- `client.py` — `AgentVanguardClient`, an httpx client mirroring the sidecar
  routes.
- `engine.py`, `firewall.py` (public SDK API), `cli/main.py` (typer CLI).

## Testing conventions

- `tests/unit/` — one module per detector/guard/component; assert exact
  `Finding`/`Verdict`/`Decision` outputs.
- `tests/integration/` — end-to-end through `Engine`/`AgentVanguard`/
  `AgentVanguardClient` (the latter spins up a real `uvicorn` server on an
  ephemeral port).
- `tests/fixtures/payloads/` — known injection/SSRF/PII/secret samples.
- No network access or API keys required — all detectors are heuristic/regex.
- Server routes build the same `PolicyInput`/`Engine.authorize()` exercised by
  `tests/unit/test_policy_evaluator.py`; route tests focus on HTTP wiring, not
  policy logic — don't duplicate policy-logic assertions there.

## Workflow notes

- Standing instruction: implement work in phases, test/lint/type-check after
  each phase before committing.
- `logs/` and `*.jsonl` are gitignored (audit log output) — don't commit
  generated audit logs.
- Active development branch: `claude/llm-agentic-firewall-design-t91kpd`.
