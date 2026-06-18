"""Guard stages: input, tool-call, output, and session.

Each module exposes `evaluate(...) -> Verdict` for its stage. `engine.Engine`
dispatches to the right guard(s) based on `PolicyInput.action` and
aggregates the resulting `Verdict`s via `policy.risk.aggregate`.
"""
