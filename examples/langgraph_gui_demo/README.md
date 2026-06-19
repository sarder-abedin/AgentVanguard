# LangGraph + Streamlit demo

A small LangGraph customer-support agent, backed by a local Ollama model,
with a Streamlit GUI that shows -- live, for every turn -- exactly what
AgentVanguard decided at each of its three trust boundaries (ingress, tool
call, output), plus the session-level repetition limit.

```
ingress_guard -> agent (LLM) -> tool_call_guard -> output_guard (tool result)
                     ^                                      |
                     +---------------- loop back ------------+
                                        |
                          output_guard (final reply) -> END
```

## Setup

1. **Install [Ollama](https://ollama.com)** and pull a model (this demo was
   tested against `llama3.2:3b` and `mistral`; any tool-calling-capable
   Ollama model works):

   ```bash
   ollama pull llama3.2:3b
   ```

2. **Install the demo extras** from the repo root:

   ```bash
   pip install -e ".[demo]"
   ```

3. **Run the GUI**:

   ```bash
   streamlit run examples/langgraph_gui_demo/app.py
   ```

   Pick the Ollama model in the sidebar (defaults to `llama3.2:3b`) and start
   chatting, or click one of the scenario presets.

## What to try

- **Benign: look up an order** -- a normal tool call, `ALLOW` end to end.
- **Prompt injection** -- "ignore all previous instructions..." is caught by
  the ingress guard before the LLM ever sees it.
- **Risky tool call: send an email** -- `send_email` is `risk_tier: high` and
  `requires_approval: true` in `agentvanguard.yaml`; with the default
  `auto_deny` approval provider this is blocked at the tool-call guard.
- **SSRF via tool argument** -- asks the agent to check a status page at
  `169.254.169.254` (the cloud metadata address); the tool-call guard's SSRF
  check denies it before the request would ever go out.
- **DLP: leak a card number** -- `lookup_order("1003")` returns a fake card
  number; the output guard redacts it from both the tool result and the
  model's final reply (`dlp.redact_credit_cards: true`).
- **Repeat to trigger the session limit** -- click this preset (or send the
  same request) more than `runtime_limits.max_repeated_calls` (3) times in
  the same browser session: the identical `lookup_order` call gets `DENY`'d
  on the 4th attempt. Session counters are tracked per `session_id` across
  the whole conversation, not per LLM turn, so repeating the request across
  turns is the reliable way to trigger this regardless of what the model
  itself decides to do.

Each decision in the side panel shows its risk score, reasons, and trace id
(`agentvanguard explain <trace_id>` against `examples/langgraph_gui_demo/logs/agentvanguard_audit.jsonl`
gives the full audit-log entry for any of them).

## Verifying without Ollama

`smoke_test.py` exercises the exact same graph with a deterministic scripted
chat model (no live LLM needed) and asserts AgentVanguard blocks/redacts at
each boundary:

```bash
python examples/langgraph_gui_demo/smoke_test.py
```

## Files

- `agentvanguard.yaml` -- policy config: `lookup_order` (low risk),
  `send_email` (high risk, requires approval), `check_status_page` (medium
  risk, used for the SSRF scenario), all scoped to the `customer_support`
  workflow.
- `tools.py` -- plain LangChain tool definitions (no AgentVanguard wrapping
  here -- see `graph.py`'s `tools_node` for why).
- `graph.py` -- the LangGraph `StateGraph`: a custom tool-execution node
  (not `langgraph.prebuilt.ToolNode`) calls `firewall.authorize`/
  `firewall.check_output` directly so every `Decision` can be surfaced to
  the GUI.
- `app.py` -- the Streamlit GUI.
- `smoke_test.py` -- Ollama-free verification harness.
