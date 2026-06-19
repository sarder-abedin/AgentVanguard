"""Hybrid local/cloud control plane: pluggable `PolicyBundleSource`s for
distributing `agentvanguard.yaml`-shaped config bundles.

See `agentvanguard.control_plane.sources` for `PolicyBundleSource`,
`LocalFileSource`, and `HttpPolicyBundleSource`. None of these sources are
wired into `Engine`/`AgentVanguard` construction automatically -- fetching a
bundle (whether locally or from a remote policy server) and rebuilding the
`Engine`/`AgentVanguard` from the resulting `Config` is the caller's
responsibility.
"""

from __future__ import annotations

from agentvanguard.control_plane.sources import (
    HttpPolicyBundleSource,
    LocalFileSource,
    PolicyBundleSource,
)

# Re-exported so callers can `from agentvanguard.control_plane import
# HttpPolicyBundleSource` etc. without reaching into the `sources` submodule
# directly.
__all__ = ["PolicyBundleSource", "LocalFileSource", "HttpPolicyBundleSource"]
