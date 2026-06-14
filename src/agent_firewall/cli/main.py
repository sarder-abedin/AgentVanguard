"""`agent-firewall` CLI (typer).

Commands: `init`, `validate-config`, `scan`, `check-ingress`, `doctor`,
`serve`, `version`. `serve` requires the `[server]` extra.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import typer
from rich.console import Console

from agent_firewall.config.defaults import DEFAULT_CONFIG_YAML
from agent_firewall.config.loader import load
from agent_firewall.core.enums import ActionKind, ProvenanceLabel
from agent_firewall.core.errors import ConfigError
from agent_firewall.core.models import PolicyInput
from agent_firewall.detectors.registry import DetectorRegistry
from agent_firewall.firewall import AgentFirewall
from agent_firewall.version import __version__

app = typer.Typer(
    name="agent-firewall",
    help="A workflow-agnostic firewall for LLM-based agentic systems.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def init(
    output: Path = typer.Option(
        Path("agent_firewall.yaml"), "--output", "-o", help="Path to write the config file."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Write an annotated default `agent_firewall.yaml`."""

    if output.exists() and not force:
        console.print(f"[red]{output} already exists. Use --force to overwrite.[/red]")
        raise typer.Exit(code=1)

    output.write_text(DEFAULT_CONFIG_YAML)
    console.print(f"[green]Wrote {output}[/green]")


@app.command(name="validate-config")
def validate_config(
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agent_firewall.yaml."),
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
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agent_firewall.yaml."),
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
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agent_firewall.yaml."),
    session_id: str | None = typer.Option(None, "--session-id", help="Session ID for runtime-limit tracking."),
) -> None:
    """Build a minimal `action=ingress` `PolicyInput` and print the `Decision`."""

    try:
        firewall = AgentFirewall.from_config(config)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    decision = firewall.authorize(
        PolicyInput(action=ActionKind.INGRESS, content=text, session_id=session_id)
    )
    console.print_json(data=decision.model_dump(mode="json"))


@app.command()
def doctor(
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agent_firewall.yaml."),
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
            probe = audit_dir / ".agent_firewall_write_test"
            probe.write_text("")
            probe.unlink()
            console.print(f"[green]Audit path writable: {audit_dir}[/green]")
        except OSError as exc:
            console.print(f"[red]Audit path not writable ({audit_dir}): {exc}[/red]")

    for extra_name, module_name in (("server", "fastapi"), ("otel", "opentelemetry")):
        installed = importlib.util.find_spec(module_name) is not None
        color = "green" if installed else "yellow"
        status = "installed" if installed else "not installed"
        console.print(f"[{color}]{extra_name} extra ({module_name}): {status}[/{color}]")


@app.command()
def serve(
    config: str | None = typer.Option(None, "--config", "-c", help="Path to agent_firewall.yaml."),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8080, "--port", help="Bind port."),
) -> None:
    """Run the agent-firewall sidecar/API service (requires the `server` extra)."""

    try:
        import uvicorn

        from agent_firewall.server.app import create_app
    except ImportError as exc:
        console.print(
            "[red]The 'server' extra is required for `agent-firewall serve`.[/red] "
            "Install it with: pip install 'agent-firewall[server]'"
        )
        raise typer.Exit(code=1) from exc

    try:
        cfg = load(config)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    uvicorn.run(create_app(cfg), host=host, port=port)


@app.command()
def version() -> None:
    """Print the agent-firewall version."""

    console.print(__version__)
