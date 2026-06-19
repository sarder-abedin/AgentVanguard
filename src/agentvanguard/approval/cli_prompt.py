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
    """Interactive, terminal-based `ApprovalProvider` for local SDK usage —
    see module docstring above for the unattended/server-deployment caveat."""

    def __init__(self, console: Console | None = None) -> None:
        # Allow a `Console` to be injected (e.g. for tests that need to
        # capture output); default to a fresh `rich` console otherwise.
        self._console = console or Console()

    def request_approval(self, decision: Decision, context: PolicyInput) -> bool:
        """Print the pending decision to the terminal and block on a y/N
        prompt; return True only if the user explicitly answers "y"/"yes".

        Prints, in order: a banner; the tool name and arguments (only when
        `context.tool` is set, i.e. this confirmation was triggered by a
        `tool_call`); the numeric `risk_score`; and every reason string
        attached to the decision, so the human has enough context to make
        an informed call without needing to inspect logs. Any other input
        (including pressing enter / leaving it blank) is treated as "no"
        — this keeps the prompt fail-closed by default, matching
        `AutoDenyApprovalProvider`'s behavior when no input is given.
        """

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
