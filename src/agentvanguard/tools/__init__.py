"""Convenience re-exports for declaring tools.

This package has no logic of its own — it is a thin, ergonomic facade over
`agentvanguard.core.models.ToolManifest` and the enums needed to populate it
(`ActionType`, `SideEffect`, `RiskTier`), so integrators writing tool
declarations don't have to import from `agentvanguard.core` directly. See
`tools/manifest.py` for the actual re-export list.
"""
