"""Heuristic, regex-based detectors for prompt injection, PII, secrets, and
exfiltration patterns.

This package intentionally contains no machine-learning or remote-API-based
detectors: every detector here is a pure, local, regex/heuristic function of
`(text, provenance)` -> `list[Finding]` (see `detectors/base.py` for the
shared `Detector` protocol). That keeps the firewall fast, dependency-free,
deterministic, and usable with no network access or API keys, which is a
testing and deployment requirement for this project (see `tests/fixtures/
payloads/` and `CLAUDE.md`).

Submodules:
- `base.py` — the `Detector` protocol every detector implements.
- `injection.py` — prompt-injection / jailbreak phrasing detector.
- `pii.py` — email/phone/SSN/credit-card detector.
- `secrets.py` — cloud credential / API key / private key detector.
- `exfil.py` — large encoded blob / oversized URL parameter detector.
- `registry.py` — builds the active `Detector` set from config.
- `redact.py` — turns `Finding.span`s into a redacted string.
"""
