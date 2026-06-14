# VanguardLLM

A workflow-agnostic firewall for LLM-based agentic systems. VanguardLLM mediates the
three universal trust boundaries in any agentic workflow — input/context, tool/action
calls, and output — to defend against prompt injection, excessive agency, data
exfiltration, SSRF, runaway loops, and memory/RAG poisoning, regardless of the agent
framework in use.

See [docs/architecture.md](docs/architecture.md) for the full firewall design: threat
model, core components, and the principles that make it applicable to any workflow.
