"""Guard stages: input, tool-call, output, and session.

Each module exposes `evaluate(...) -> Verdict` for its stage. `engine.Engine`
dispatches to the right guard(s) based on `PolicyInput.action` and
aggregates the resulting `Verdict`s via `policy.risk.aggregate`.

This package intentionally has no other exports: it is a pure grouping of
sibling modules (`input_guard`, `tool_guard`, `output_guard`,
`session_guard`), each importable on its own, e.g.
`from agentvanguard.guards import tool_guard`. There is no shared base class
or registry here — the contract between a guard module and `engine.Engine`
is purely structural: expose a module-level `evaluate(...)` function that
takes the relevant inputs (a `PolicyInput`, the active `Config`, and
whatever stage-specific collaborators it needs, e.g. a `DetectorRegistry` or
`SessionState`) and returns a single `Verdict` for that stage.
"""
