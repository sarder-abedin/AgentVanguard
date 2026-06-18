"""Interactive approval provider for local development.

Prints the decision (reasons, risk score, and — for tool calls — the tool
name and arguments) and blocks on a y/N prompt. Not suitable for unattended
or server deployments; configure `firewall.approval_provider: cli_prompt`
only for local SDK usage.
"""

from __future__ import annotations

from rich.console import Console

from agentvanguard.core.models import Decision, PolicyInput


class CLIApprovalProvider:
    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def request_approval(self, decision: Decision, context: PolicyInput) -> bool:
        self._console.print("[bold yellow]agentvanguard: confirmation required[/bold yellow]")
        if context.tool:
            self._console.print(f"  tool: {context.tool}")
            if context.arguments:
                self._console.print(f"  arguments: {context.arguments}")
        self._console.print(f"  risk_score: {decision.risk_score:.2f}")
        for reason in decision.reasons:
            self._console.print(f"  - {reason}")
        answer = input("Allow this action? [y/N]: ").strip().lower()
        return answer in ("y", "yes")
