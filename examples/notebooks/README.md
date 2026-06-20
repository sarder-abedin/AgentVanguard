# AgentVanguard notebook tutorials

Four short, runnable Jupyter notebooks that walk through AgentVanguard's
core features, each building on the last. No network access, API keys, or
running services are required -- every check runs locally against the
example policy in [`examples/agentvanguard.yaml`](../agentvanguard.yaml).

| # | Notebook | Covers |
|---|---|---|
| 1 | [`01_sdk_basics.ipynb`](01_sdk_basics.ipynb) | `authorize()`, `check_output()`, the `Decision` object, ingress prompt-injection detection, output DLP redaction vs. the secret hard-stop |
| 2 | [`02_tool_broker.ipynb`](02_tool_broker.ipynb) | `ToolManifest`, `@firewall.tool`/`wrap_tool`, approval-required tools, the SSRF check, the path-traversal check |
| 3 | [`03_sessions_limits_audit.ipynb`](03_sessions_limits_audit.ipynb) | Session-scoped `runtime_limits`, the repeated-call/runaway-loop guard, reading the JSONL audit log by `trace_id` |
| 4 | [`04_full_agent_loop.ipynb`](04_full_agent_loop.ipynb) | `wrap_agent` + `wrap_tool` combined around one mock multi-turn agent |

## Setup

```bash
# from the repo root
pip install -e ".[notebooks]"   # or: pip install -r requirements.txt
jupyter lab examples/notebooks/01_sdk_basics.ipynb
```

Work through them in order -- each one assumes the concepts from the
previous notebook. For a live, LLM-backed version of the same ideas, see
[`examples/langgraph_gui_demo/`](../langgraph_gui_demo/); for plain Python
scripts instead of notebooks, see
[`sdk_quickstart.py`](../sdk_quickstart.py),
[`tool_broker_quickstart.py`](../tool_broker_quickstart.py), and
[`mock_agent_loop.py`](../mock_agent_loop.py).
