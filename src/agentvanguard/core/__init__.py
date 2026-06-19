"""Core types: enums, pydantic models, and shared exceptions.

This package intentionally has no submodule re-exports here — callers import
directly from `agentvanguard.core.enums`, `agentvanguard.core.models`, and
`agentvanguard.core.errors`. It exists to group the dependency-free building
blocks (no policy logic, no I/O) that every other package in `agentvanguard`
(config, detectors, policy, guards, engine, integrations) depends on.
"""
