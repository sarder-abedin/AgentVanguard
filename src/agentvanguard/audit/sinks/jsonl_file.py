"""Default `AuditSink`: append-only JSON Lines file."""

from __future__ import annotations

from pathlib import Path

from agentvanguard.audit.events import AuditEvent


class JsonlFileSink:
    """Appends one JSON object per line to `path`, creating parent
    directories on first write.

    This is the default `AuditSink` (`config.audit.backend == "jsonl"`):
    every `AuditEvent` becomes exactly one line of compact JSON, so the file
    is both human-greppable and trivially streamable/parseable line-by-line
    by external log shippers (Filebeat, Fluentd, etc.) without needing to
    buffer the whole file. The file is opened in append mode for every
    write, so multiple processes/threads writing to the same path interleave
    safely at the line level (subject to OS-level append guarantees) without
    needing to hold the file open.
    """

    def __init__(self, path: str) -> None:
        # `path` is the on-disk destination for the JSONL audit log (e.g.
        # `logs/audit.jsonl`, per `config.audit.path`). Resolved to a `Path`
        # once so every `write()` doesn't need to re-parse the string.
        self.path = Path(path)

    def write(self, event: AuditEvent) -> None:
        # Ensure the parent directory exists before every write rather than
        # once at construction time -- this makes the sink robust to the
        # directory being deleted/recreated between writes (e.g. log
        # rotation tooling that moves the whole directory), at the cost of a
        # cheap no-op `mkdir` check on the common path.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Open-append-close per event (rather than keeping a long-lived file
        # handle) trades a small amount of per-write overhead for
        # simplicity and crash-safety: there is no handle to leak or flush
        # on shutdown, and a process crash never loses a write that already
        # returned from this call.
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(event.model_dump_json() + "\n")
