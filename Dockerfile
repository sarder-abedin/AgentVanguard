# Sidecar/API service image for agentvanguard (Phase 2).
#
# Ships a working default config (written via `agentvanguard init`) so the
# container is usable out of the box. Override it either by mounting your own
# file over /app/agentvanguard.yaml, or by setting AGENTVANGUARD_CONFIG to a
# different path (e.g. a ConfigMap mount in Kubernetes) -- config/loader.py
# resolves AGENTVANGUARD_CONFIG before falling back to ./agentvanguard.yaml.
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir ".[server]"

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin agentvanguard \
    && mkdir -p /app/logs \
    && agentvanguard init -o /app/agentvanguard.yaml \
    && chown -R agentvanguard:agentvanguard /app

USER agentvanguard

EXPOSE 8080

ENTRYPOINT ["agentvanguard", "serve", "--host", "0.0.0.0", "--port", "8080"]
