"""Default `AuditSink`: append-only JSON Lines file."""

from __future__ import annotations

from pathlib import Path

from agent_firewall.audit.events import AuditEvent


class JsonlFileSink:
    """Appends one JSON object per line to `path`, creating parent
    directories on first write."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def write(self, event: AuditEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(event.model_dump_json() + "\n")
