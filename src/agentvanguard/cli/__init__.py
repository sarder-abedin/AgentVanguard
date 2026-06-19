"""Command-line interface for agentvanguard.

This package contains only `main.py`, which defines the `agentvanguard`
typer `app` (the console-script entry point installed by `pyproject.toml`).
Kept separate from `main.py` itself so the CLI has its own namespace
(`agentvanguard.cli.main:app`) distinct from the SDK/engine packages.
"""
