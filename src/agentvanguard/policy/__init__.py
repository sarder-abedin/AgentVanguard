"""Risk scoring, rule matching, and verdict aggregation.

This package is the policy "brain" sitting between the guards
(`agentvanguard.guards`) and the engine (`agentvanguard.engine.Engine`):

- `evaluator.py` (`PolicyEvaluator`) — the single dispatch point that maps a
  `PolicyInput.action` to the guard stage(s) that should run, plus
  evaluation of custom `rules:` from config. Produces a `list[Verdict]`.
- `matcher.py` — interprets the `match` dict on a custom `rules:` entry
  (tool/workflow/agent/actor/provenance/finding-type/risk-score predicates)
  against a `PolicyInput` and the findings/risk score produced so far.
- `risk.py` — deterministic numeric scoring of individual `Finding`s
  (severity * provenance multiplier) and the worst-action-wins reduction of
  a `list[Verdict]` into the single `Decision` returned to the caller.

Nothing in this package talks to detectors, config loading, or session
storage directly except through the objects passed in by callers
(`Engine.authorize()` is the only caller) — it is pure decision logic.
"""
