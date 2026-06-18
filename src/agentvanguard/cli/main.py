"""`agentvanguard` CLI (typer).

Commands: `init`, `quickstart`, `validate-config`, `scan`, `check-ingress`,
`explain`, `doctor`, `serve`, `version`. `serve` requires the `[server]`
extra.
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

app = typer.Typer(
    name="agentvanguard",
    help="A workflow-agnostic firewall for LLM-based agentic systems.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def init(
    output: Path = typer.Option(
        Path("agentvanguard.yaml"), "--output", "-o", help="Path to write the config file."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Write an annotated default `agentvanguard.yaml`."""

    if output.exists() and not force:
        console.print(f"[red]{output} already exists. Use --force to overwrite.[/red]")
        raise typer.Exit(code=1)

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

_QUICKSTART_DEFAULT_TOOLS: dict[str, ActionType] = {
    "lookup_order": ActionType.READ,
    "send_email": ActionType.SEND_EXTERNAL,
}

_CONSERVATIVE_RUNTIME_LIMITS = RuntimeLimits(
    max_steps=8, max_tool_calls=5, max_runtime_seconds=30, max_cost_usd=1.00, max_repeated_calls=2
)


def _tool_config_for(action_type: ActionType) -> ToolConfig:
    side_effect, risk_tier, requires_approval, reversible = _ACTION_TYPE_DEFAULTS[action_type]
    return ToolConfig(
        action_type=action_type,
        side_effect=side_effect,
        risk_tier=risk_tier,
        requires_approval=requires_approval,
        reversible=reversible,
    )


def _prompt_modes() -> set[str]:
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
    return Config(
        firewall=FirewallSection(approval_provider=approval_provider),
        runtime_limits=_CONSERVATIVE_RUNTIME_LIMITS if conservative else RuntimeLimits(),
        tools={name: _tool_config_for(action_type) for name, action_type in tools.items()},
    )


def _print_next_steps(modes: set[str], config_path: Path) -> None:
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

    if output.exists() and not force:
        console.print(f"[red]{output} already exists. Use --force to overwrite.[/red]")
        raise typer.Exit(code=1)

    console.print("[bold]AgentVanguard quickstart[/bold]")

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

    config = _build_quickstart_config(tools, approval_provider, conservative)
    errors = config.validate_references()
    if errors:
        console.print("[red]Generated config failed validation:[/red]")
        for error in errors:
            console.print(f"  - {error}")
        raise typer.Exit(code=1)

    output.write_text(yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False))
    console.print(f"\n[green]Wrote {output}[/green]")
    _print_next_steps(modes, output)


@app.command(name="validate-config")
def validate_config(
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agentvanguard.yaml."),
) -> None:
    """Load and validate a config file (including cross-references)."""

    try:
        cfg = load(config)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(code=1) from exc

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

    try:
        cfg = load(config)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    detectors = DetectorRegistry.from_config(cfg)
    findings = detectors.detect_all(text, provenance)
    console.print_json(data=[f.model_dump(mode="json") for f in findings])


@app.command(name="check-ingress")
def check_ingress(
    text: str = typer.Option(..., "--text", "-t", help="Text to authorize as ingress content."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agentvanguard.yaml."),
    session_id: str | None = typer.Option(None, "--session-id", help="Session ID for runtime-limit tracking."),
) -> None:
    """Build a minimal `action=ingress` `PolicyInput` and print the `Decision`."""

    try:
        firewall = AgentVanguard.from_config(config)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    decision = firewall.authorize(
        PolicyInput(action=ActionKind.INGRESS, content=text, session_id=session_id)
    )
    console.print_json(data=decision.model_dump(mode="json"))


_SEVERITY_COLOR = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
_DECISION_COLOR = {
    "ALLOW": "green",
    "ALLOW_WITH_MODIFICATIONS": "yellow",
    "REQUIRE_USER_CONFIRMATION": "yellow",
    "DENY": "red",
}


def _print_audit_event(event: dict) -> None:
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

    try:
        cfg = load(config)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    audit_path = Path(cfg.audit.path)
    if not audit_path.exists():
        console.print(f"[red]Audit log not found: {audit_path}[/red]")
        raise typer.Exit(code=1)

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

    console.print(f"Python: {sys.version.split()[0]}")

    cfg = None
    try:
        cfg = load(config)
        console.print("[green]Config: OK[/green]")
    except ConfigError as exc:
        console.print(f"[red]Config: {exc}[/red]")

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

    configure_logging(cfg.firewall.log_level)
    uvicorn.run(create_app(cfg), host=host, port=port, log_config=None)


@app.command()
def version() -> None:
    """Print the agentvanguard version."""

    console.print(__version__)
