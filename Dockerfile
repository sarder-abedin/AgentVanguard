# Sidecar/API service image for agent-firewall (Phase 2).
#
# Ships a working default config (written via `agent-firewall init`) so the
# container is usable out of the box. Override it either by mounting your own
# file over /app/agent_firewall.yaml, or by setting AGENT_FIREWALL_CONFIG to a
# different path (e.g. a ConfigMap mount in Kubernetes) -- config/loader.py
# resolves AGENT_FIREWALL_CONFIG before falling back to ./agent_firewall.yaml.
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir ".[server]"

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin agentfirewall \
    && mkdir -p /app/logs \
    && agent-firewall init -o /app/agent_firewall.yaml \
    && chown -R agentfirewall:agentfirewall /app

USER agentfirewall

EXPOSE 8080

ENTRYPOINT ["agent-firewall", "serve", "--host", "0.0.0.0", "--port", "8080"]
