"""`agentvanguard` CLI (typer).

Commands: `init`, `quickstart`, `validate-config`, `scan`, `check-ingress`,
`explain`, `doctor`, `serve`, `version`. `serve` requires the `[server]`
extra.

Every command below is a thin wrapper: it parses CLI flags, calls into the
SDK (`config/loader.load`, `AgentVanguard`, `DetectorRegistry`, etc.) the
same way any other integration surface would, and renders the result with
`rich`. No command re-implements policy/config logic itself -- that would
violate the project's "single shared `Engine`" invariant.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Literal

import typer
import yaml
from rich.console import Console

from agentvanguard.config.defaults import DEFAULT_CONFIG_YAML
from agentvanguard.config.loader import load
from agentvanguard.config.schema import Config, FirewallSection, RuntimeLimits, ToolConfig
from agentvanguard.core.enums import ActionKind, ActionType, ProvenanceLabel, RiskTier, SideEffect
from agentvanguard.core.errors import ConfigError
from agentvanguard.core.models import PolicyInput
from agentvanguard.detectors.registry import DetectorRegistry
from agentvanguard.firewall import AgentVanguard
from agentvanguard.observability.logging import configure_logging
from agentvanguard.version import __version__

# The root typer app; `no_args_is_help=True` means running `agentvanguard`
# with no subcommand prints help instead of doing nothing. This object is
# the `agentvanguard` console-script entry point (see `pyproject.toml`'s
# `[project.scripts]`).
app = typer.Typer(
    name="agentvanguard",
    help="A workflow-agnostic firewall for LLM-based agentic systems.",
    no_args_is_help=True,
)
# Shared `rich` console used by every command below for colorized output
# (e.g. `[red]...[/red]` for errors, `[green]...[/green]` for success).
console = Console()


@app.command()
def init(
    output: Path = typer.Option(
        Path("agentvanguard.yaml"), "--output", "-o", help="Path to write the config file."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Write an annotated default `agentvanguard.yaml`."""

    # Fail closed by default: never silently clobber an existing config
    # file unless the caller explicitly opts in with `--force`.
    if output.exists() and not force:
        console.print(f"[red]{output} already exists. Use --force to overwrite.[/red]")
        raise typer.Exit(code=1)

    # `DEFAULT_CONFIG_YAML` (from config/defaults.py) is a static, annotated
    # YAML template -- not derived from `Config()` -- so it can carry inline
    # comments explaining each section to a first-time user.
    output.write_text(DEFAULT_CONFIG_YAML)
    console.print(f"[green]Wrote {output}[/green]")


# action_type -> (side_effect, risk_tier, requires_approval, reversible),
# used by `quickstart` to turn a one-word answer into a safe-by-default
# `ToolConfig` without the user needing to learn the risk model up front.
_ACTION_TYPE_DEFAULTS: dict[ActionType, tuple[SideEffect, RiskTier, bool, bool]] = {
    ActionType.READ: (SideEffect.INTERNAL_READ, RiskTier.LOW, False, True),
    ActionType.WRITE: (SideEffect.INTERNAL_WRITE, RiskTier.MEDIUM, False, True),
    ActionType.EXECUTE: (SideEffect.IRREVERSIBLE_CHANGE, RiskTier.HIGH, True, False),
    ActionType.SEND_EXTERNAL: (SideEffect.EXTERNAL_COMMUNICATION, RiskTier.HIGH, True, False),
    ActionType.DELETE: (SideEffect.IRREVERSIBLE_CHANGE, RiskTier.HIGH, True, False),
    ActionType.FINANCIAL: (SideEffect.FINANCIAL_TRANSACTION, RiskTier.CRITICAL, True, False),
}

# Fallback tool set offered by `_prompt_tools()` when the user asks for
# zero custom tools -- gives `quickstart` a non-empty, schema-valid `tools:`
# section to write out and lets the user see one `read` and one
# `send_external` example to edit later instead of starting from nothing.
_QUICKSTART_DEFAULT_TOOLS: dict[str, ActionType] = {
    "lookup_order": ActionType.READ,
    "send_email": ActionType.SEND_EXTERNAL,
}

# Tighter-than-default `RuntimeLimits` offered by `quickstart` when the user
# opts into "conservative" mode -- lower step/call/time/cost/repeat caps so
# a first, unfamiliar run fails closed quickly rather than racking up many
# tool calls or cost before a problem is noticed.
_CONSERVATIVE_RUNTIME_LIMITS = RuntimeLimits(
    max_steps=8, max_tool_calls=5, max_runtime_seconds=30, max_cost_usd=1.00, max_repeated_calls=2
)


def _tool_config_for(action_type: ActionType) -> ToolConfig:
    """Build a safe-by-default `ToolConfig` for `action_type`, using the
    `(side_effect, risk_tier, requires_approval, reversible)` tuple looked
    up from `_ACTION_TYPE_DEFAULTS`. Used by `quickstart` to turn the user's
    one-word answer (e.g. "read", "send_external") into a fully-formed,
    schema-valid tool entry without making them learn the risk model."""

    side_effect, risk_tier, requires_approval, reversible = _ACTION_TYPE_DEFAULTS[action_type]
    return ToolConfig(
        action_type=action_type,
        side_effect=side_effect,
        risk_tier=risk_tier,
        requires_approval=requires_approval,
        reversible=reversible,
    )


def _prompt_modes() -> set[str]:
    """Interactively ask the `quickstart` user which integration surface(s)
    they plan to use (in-process SDK, ASGI middleware, or HTTP sidecar) so
    `_print_next_steps()` can later print only the relevant instructions.
    Multiple modes may be selected; if none are, defaults to `"sdk"` so the
    wizard always has at least one mode to act on."""

    console.print("\n[bold]How will your agent(s) use AgentVanguard?[/bold] (you can pick more than one)")
    modes = set()
    if typer.confirm("  Call it directly as a Python SDK / tool-broker (in-process)?", default=True):
        modes.add("sdk")
    if typer.confirm("  Put it in front of an existing HTTP service as ASGI middleware?", default=False):
        modes.add("asgi")
    if typer.confirm("  Run it as a standalone HTTP sidecar (separate service/container)?", default=False):
        modes.add("sidecar")
    if not modes:
        console.print("  No mode selected -- defaulting to SDK / tool-broker.")
        modes.add("sdk")
    return modes


def _prompt_tools() -> dict[str, ActionType]:
    """Interactively collect the tool names and `ActionType`s the
    `quickstart` user wants to register, returning a `{name: ActionType}`
    mapping that `_build_quickstart_config` turns into `ToolConfig`s.

    Asking "how many tools" up front (rather than looping until the user
    types a sentinel) keeps the prompt flow simple; entering `0` short-
    circuits to `_QUICKSTART_DEFAULT_TOOLS` so there's still something to
    write out and edit. An unrecognized action-type string is reported and
    downgraded to `ActionType.READ` (the least-privileged choice) rather
    than aborting the wizard.
    """

    console.print(
        "\n[bold]Tools[/bold] -- every tool your agent can call must be declared, or it is DENY'd by default."
    )
    count = typer.prompt(
        "How many tools do you want to register now? (0 to start from two examples you can edit later)",
        default=0,
        type=int,
    )
    if count <= 0:
        console.print("  Using example tools: lookup_order (read), send_email (send_external).")
        return dict(_QUICKSTART_DEFAULT_TOOLS)

    action_choices = ", ".join(a.value for a in ActionType)
    tools: dict[str, ActionType] = {}
    for i in range(count):
        name = typer.prompt(f"  Tool #{i + 1} name")
        raw_action_type = typer.prompt(f"  Tool #{i + 1} action type ({action_choices})", default="read")
        try:
            action_type = ActionType(raw_action_type)
        except ValueError:
            console.print(f"  [yellow]Unrecognized action type '{raw_action_type}', defaulting to 'read'.[/yellow]")
            action_type = ActionType.READ
        tools[name] = action_type
    return tools


def _build_quickstart_config(
    tools: dict[str, ActionType],
    approval_provider: Literal["auto_deny", "cli_prompt"],
    conservative: bool,
) -> Config:
    """Assemble the final `Config` for `quickstart` from the answers
    gathered by `_prompt_tools()` and the approval-provider/conservative-
    limits choices made in the `quickstart` command body. Each `tools`
    entry is converted to a `ToolConfig` via `_tool_config_for`; runtime
    limits are `_CONSERVATIVE_RUNTIME_LIMITS` or the schema defaults
    depending on `conservative`."""

    return Config(
        firewall=FirewallSection(approval_provider=approval_provider),
        runtime_limits=_CONSERVATIVE_RUNTIME_LIMITS if conservative else RuntimeLimits(),
        tools={name: _tool_config_for(action_type) for name, action_type in tools.items()},
    )


def _print_next_steps(modes: set[str], config_path: Path) -> None:
    """Print copy-pasteable usage snippets for each integration mode the
    `quickstart` user selected in `_prompt_modes()` (SDK/tool-broker, ASGI
    middleware, HTTP sidecar), referencing the just-written `config_path`,
    plus a closing pointer to `agentvanguard doctor` to verify the setup."""

    console.print("\n[bold]Next steps[/bold]")

    if "sdk" in modes:
        console.print(
            "\n[bold]SDK / tool-broker[/bold] (see examples/sdk_quickstart.py, "
            "examples/tool_broker_quickstart.py):\n"
            f"  firewall = AgentVanguard.from_config({str(config_path)!r})\n"
            '  safe_tool = firewall.wrap_tool("<tool_name>", my_tool_fn)'
        )

    if "asgi" in modes:
        console.print(
            "\n[bold]ASGI middleware[/bold]:\n"
            "  from agentvanguard.integrations.asgi import AgentVanguardMiddleware\n"
            f"  firewall = AgentVanguard.from_config({str(config_path)!r})\n"
            "  app = AgentVanguardMiddleware(app, firewall)"
        )

    if "sidecar" in modes:
        console.print(
            "\n[bold]HTTP sidecar[/bold]:\n"
            f"  agentvanguard serve --config {config_path} --port 8080\n"
            "  curl http://127.0.0.1:8080/healthz"
        )

    console.print(f"\nVerify the setup with: [bold]agentvanguard doctor --config {config_path}[/bold]")


@app.command()
def quickstart(
    output: Path = typer.Option(
        Path("agentvanguard.yaml"), "--output", "-o", help="Path to write the config file."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Interactive wizard: answer a few questions to generate a tailored,
    schema-valid `agentvanguard.yaml`, then print the exact next step for the
    integration mode(s) you picked. Does not remove or replace `init` --
    use whichever is faster for you."""

    # Same overwrite-protection as `init`: never clobber an existing file
    # without `--force`.
    if output.exists() and not force:
        console.print(f"[red]{output} already exists. Use --force to overwrite.[/red]")
        raise typer.Exit(code=1)

    console.print("[bold]AgentVanguard quickstart[/bold]")

    # Gather the wizard's three inputs: which surface(s) to integrate with,
    # which tools to declare, and the approval/runtime-limit posture.
    modes = _prompt_modes()
    tools = _prompt_tools()

    console.print("\n[bold]Approvals[/bold]")
    use_cli_prompt = typer.confirm(
        "  Prompt interactively for high-risk actions instead of auto-denying them? "
        "(local dev only -- auto_deny is the safe default for anything unattended)",
        default=False,
    )
    approval_provider: Literal["auto_deny", "cli_prompt"] = "cli_prompt" if use_cli_prompt else "auto_deny"

    console.print("\n[bold]Runtime limits[/bold]")
    conservative = typer.confirm(
        "  Use conservative runtime limits (lower step/cost/budget caps, recommended for a first run)?",
        default=True,
    )

    # Build the `Config` from the collected answers, then re-run the same
    # cross-reference validation `validate-config`/`load()` would run --
    # catches e.g. a workflow referencing a tool that was never declared --
    # before anything is written to disk.
    config = _build_quickstart_config(tools, approval_provider, conservative)
    errors = config.validate_references()
    if errors:
        console.print("[red]Generated config failed validation:[/red]")
        for error in errors:
            console.print(f"  - {error}")
        raise typer.Exit(code=1)

    # Unlike `init` (which writes a static annotated template), `quickstart`
    # serializes the actual constructed `Config` object via pydantic's
    # `model_dump` -- so the file on disk exactly reflects the wizard's
    # answers, at the cost of losing the explanatory inline comments
    # `DEFAULT_CONFIG_YAML` has.
    output.write_text(yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False))
    console.print(f"\n[green]Wrote {output}[/green]")
    _print_next_steps(modes, output)


@app.command(name="validate-config")
def validate_config(
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agentvanguard.yaml."),
) -> None:
    """Load and validate a config file (including cross-references)."""

    # `load()` does the full pipeline: resolve the path, parse YAML,
    # validate against the pydantic `Config` schema, and run
    # `Config.validate_references()` for cross-section checks (e.g. a
    # workflow's `allowed_tools` referencing an undeclared tool). Any
    # failure surfaces as `ConfigError` with a human-readable message.
    try:
        cfg = load(config)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # On success, print a quick summary so the user can sanity-check that
    # the expected number of tools/workflows/rules were picked up.
    console.print("[green]Config is valid.[/green]")
    console.print(f"  tools: {len(cfg.tools)}")
    console.print(f"  workflows: {len(cfg.workflows)}")
    console.print(f"  rules: {len(cfg.rules)}")


@app.command()
def scan(
    text: str = typer.Option(..., "--text", "-t", help="Text to scan for findings."),
    provenance: ProvenanceLabel = typer.Option(
        ProvenanceLabel.USER, "--provenance", "-p", help="Provenance label used for risk scoring."
    ),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agentvanguard.yaml."),
) -> None:
    """Run the configured detectors over `--text` and print `Finding[]` as JSON."""

    # This is a detector-only smoke test: it runs the same `DetectorRegistry`
    # the engine uses, but does *not* go through `Engine.authorize()` --
    # there's no `Decision`, no session-state mutation, no audit log entry.
    # Useful for quickly checking "does my prompt-injection/PII/secret regex
    # fire on this string?" without standing up a full `PolicyInput`.
    try:
        cfg = load(config)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    detectors = DetectorRegistry.from_config(cfg)
    # `provenance` affects risk scoring inside each detector (e.g. the same
    # text may be scored differently if it's user input vs. a tool output),
    # so it's exposed as a flag rather than hardcoded.
    findings = detectors.detect_all(text, provenance)
    console.print_json(data=[f.model_dump(mode="json") for f in findings])


@app.command(name="check-ingress")
def check_ingress(
    text: str = typer.Option(..., "--text", "-t", help="Text to authorize as ingress content."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agentvanguard.yaml."),
    session_id: str | None = typer.Option(None, "--session-id", help="Session ID for runtime-limit tracking."),
) -> None:
    """Build a minimal `action=ingress` `PolicyInput` and print the `Decision`."""

    # Unlike `scan`, this command goes through the real `AgentVanguard` SDK
    # entry point -> `Engine.authorize()` -> full ingress guard pipeline
    # (detectors, risk aggregation, approval, session-state update, audit
    # logging) -- the same path a real ingress request would take. Useful
    # for testing "what would my firewall actually decide for this input?"
    # from the command line, including session-scoped runtime-limit
    # tracking if `--session-id` is given.
    try:
        firewall = AgentVanguard.from_config(config)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    decision = firewall.authorize(
        PolicyInput(action=ActionKind.INGRESS, content=text, session_id=session_id)
    )
    console.print_json(data=decision.model_dump(mode="json"))


# Color lookup tables shared by `_print_audit_event` for rendering
# severities and decisions consistently with the rest of the CLI's
# `rich`-based output (e.g. red for DENY/critical, green for ALLOW/low).
_SEVERITY_COLOR = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
_DECISION_COLOR = {
    "ALLOW": "green",
    "ALLOW_WITH_MODIFICATIONS": "yellow",
    "REQUIRE_USER_CONFIRMATION": "yellow",
    "DENY": "red",
}


def _print_audit_event(event: dict) -> None:
    """Render one parsed audit-log JSON object (as produced by
    `AuditLogger`/the `jsonl` sink) as human-readable, colorized text for
    `explain`: timestamp/action/session header, decision + risk score,
    each `Finding` that contributed to the decision, and the `Decision`'s
    `reasons`. `event` is treated as a loosely-typed `dict` (not a pydantic
    model) since it's been round-tripped through JSON from disk; every
    field access uses `.get(..., default)` so a missing/older-schema field
    degrades to a placeholder instead of raising.
    """

    decision = event.get("decision", "?")
    decision_color = _DECISION_COLOR.get(decision, "white")

    console.print(
        f"\n[bold]{event.get('timestamp', '?')}[/bold]  "
        f"action={event.get('action', '?')}  session={event.get('session_id') or '-'}"
    )
    console.print(
        f"decision: [{decision_color}]{decision}[/{decision_color}]  "
        f"risk_score: {event.get('risk_score', 0.0):.2f}"
    )

    findings = event.get("findings") or []
    if findings:
        console.print("findings:")
        for finding in findings:
            severity = finding.get("severity", "?")
            severity_color = _SEVERITY_COLOR.get(severity, "white")
            console.print(
                f"  - [{severity_color}]{finding.get('type', '?')}[/{severity_color}] "
                f"(detector={finding.get('detector', '?')}, severity={severity}): {finding.get('message', '')}"
            )
    else:
        console.print("findings: none")

    reasons = event.get("reasons") or []
    if reasons:
        console.print("reasons:")
        for reason in reasons:
            console.print(f"  - {reason}")


@app.command()
def explain(
    trace_id: str = typer.Argument(..., help="trace_id from a Decision or audit log entry to explain."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agentvanguard.yaml."),
) -> None:
    """Look up `trace_id` in the audit log and print a human-readable
    breakdown of why that decision was made -- every `Finding` (type,
    detector, severity, message), the aggregated risk score, and the final
    decision with its reasons. Reads data the engine already recorded; does
    not re-evaluate or change the decision."""

    # `cfg.audit.path` tells us where the `jsonl` audit sink writes events
    # (same config the engine itself uses), so `explain` looks in exactly
    # the file the run-in-question would have written to.
    try:
        cfg = load(config)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    audit_path = Path(cfg.audit.path)
    if not audit_path.exists():
        console.print(f"[red]Audit log not found: {audit_path}[/red]")
        raise typer.Exit(code=1)

    # The audit log is JSON Lines: one JSON object per line, append-only.
    # `trace_id` is unique per `Decision`, but in principle multiple lines
    # could share one (e.g. a future multi-event-per-decision audit
    # format), so collect *all* matches rather than assuming exactly one.
    matches = []
    for line in audit_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        event = json.loads(line)
        if event.get("trace_id") == trace_id:
            matches.append(event)

    if not matches:
        console.print(f"[red]No audit event found for trace_id '{trace_id}' in {audit_path}[/red]")
        raise typer.Exit(code=1)

    for event in matches:
        _print_audit_event(event)


@app.command()
def doctor(
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agentvanguard.yaml."),
) -> None:
    """Check config validity, audit-path writability, Python version, and
    which optional extras are installed."""

    # `doctor` is a pre-flight diagnostic: it doesn't fix anything, just
    # surfaces the most common reasons a deployment would fail (bad config,
    # un-writable audit directory, missing optional dependency) before the
    # user tries to actually run `serve` or wire the SDK into their agent.
    console.print(f"Python: {sys.version.split()[0]}")

    cfg = None
    try:
        cfg = load(config)
        console.print("[green]Config: OK[/green]")
    except ConfigError as exc:
        console.print(f"[red]Config: {exc}[/red]")

    # Only probe the audit path if the config loaded successfully --
    # otherwise there's no `cfg.audit.path` to check. The probe writes and
    # immediately deletes a throwaway file rather than checking
    # `os.access()`, since that's a more reliable test of *actual*
    # writability (covers read-only filesystems, permission edge cases,
    # etc.) than permission-bit inspection alone.
    if cfg is not None:
        audit_dir = Path(cfg.audit.path).parent
        try:
            audit_dir.mkdir(parents=True, exist_ok=True)
            probe = audit_dir / ".agentvanguard_write_test"
            probe.write_text("")
            probe.unlink()
            console.print(f"[green]Audit path writable: {audit_dir}[/green]")
        except OSError as exc:
            console.print(f"[red]Audit path not writable ({audit_dir}): {exc}[/red]")

    # Report which optional extras (`[server]`, `[otel]`, `[metrics]`,
    # `[redis]`) are installed by probing for their underlying third-party
    # package via `importlib.util.find_spec` -- this mirrors exactly the
    # check each optional module (`observability/metrics.py`,
    # `observability/tracing.py`, etc.) does internally via its own
    # try/except ImportError, surfaced here for human inspection instead of
    # runtime branching.
    for extra_name, module_name in (
        ("server", "fastapi"),
        ("otel", "opentelemetry"),
        ("metrics", "prometheus_client"),
        ("redis", "redis"),
    ):
        installed = importlib.util.find_spec(module_name) is not None
        color = "green" if installed else "yellow"
        status = "installed" if installed else "not installed"
        console.print(f"[{color}]{extra_name} extra ({module_name}): {status}[/{color}]")


@app.command()
def serve(
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agentvanguard.yaml."),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8080, "--port", help="Bind port."),
) -> None:
    """Run the agentvanguard sidecar/API service (requires the `server` extra)."""

    # `uvicorn`/`server.app` are imported lazily (inside the function, not
    # at module top-level) so the rest of the CLI (`init`, `scan`,
    # `validate-config`, etc.) stays usable without the `[server]` extra
    # installed -- only `serve` itself requires it, and only at the moment
    # it's actually invoked.
    try:
        import uvicorn

        from agentvanguard.server.app import create_app
    except ImportError as exc:
        console.print(
            "[red]The 'server' extra is required for `agentvanguard serve`.[/red] "
            "Install it with: pip install 'agentvanguard[server]'"
        )
        raise typer.Exit(code=1) from exc

    try:
        cfg = load(config)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # Install the structured JSON logging handler (see
    # `observability/logging.py`) before starting uvicorn, using the log
    # level from `firewall.log_level` in the loaded config. `log_config=None`
    # disables uvicorn's own default logging setup so it doesn't fight with
    # (or override) the handler `configure_logging` just installed.
    configure_logging(cfg.firewall.log_level)
    uvicorn.run(create_app(cfg), host=host, port=port, log_config=None)


@app.command()
def version() -> None:
    """Print the agentvanguard version."""

    # `__version__` is the single source of truth for the package version
    # (agentvanguard/version.py); printing it here gives users/scripts a
    # simple way to check it without importing the package in Python.
    console.print(__version__)
