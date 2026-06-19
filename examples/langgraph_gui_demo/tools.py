"""Plain tool implementations for the LangGraph demo.

These are intentionally *not* wrapped with `firewall.wrap_tool` here: the
graph's custom tool-execution node (`graph.py`) is the single place that
calls `firewall.authorize(action="tool_call")` and `firewall.check_output`,
so it can surface every `Decision` -- including `ALLOW`s -- to the GUI's
decision panel without mediating each call twice or double-counting session
limits (`max_tool_calls`/`max_repeated_calls`).

Each tool's manifest (risk tier, side effect, allowed callers, ...) is
declared in `agentvanguard.yaml` under `tools:`, not here.
"""

from __future__ import annotations

from langchain_core.tools import tool

_ORDERS = {
    "1001": "Order 1001: 2x wireless mouse, status=delivered, shipped to alice@example.com",
    "1002": "Order 1002: 1x mechanical keyboard, status=in transit",
    "1003": "Order 1003: 1x laptop stand, status=delivered, card on file 4111 1111 1111 1111",
}


@tool
def lookup_order(order_id: str) -> str:
    """Look up an order by its ID and return its status."""

    return _ORDERS.get(order_id, f"No order found with id {order_id}")


@tool
def send_email(to: str, body: str) -> str:
    """Send an email to a customer. Requires human approval."""

    return f"[demo] would send email to {to}: {body}"


@tool
def check_status_page(url: str) -> str:
    """Fetch a vendor's public status page by URL to check for outages."""

    return f"[demo] fetched status page {url}: all systems operational"


def build_tools() -> list:
    return [lookup_order, send_email, check_status_page]
