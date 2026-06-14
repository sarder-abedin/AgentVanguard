# agent-firewall on Kubernetes

Vendor-neutral manifests for running the agent-firewall sidecar/API service
(`agent-firewall serve`) as a `Deployment` + `Service`, configured via a
`ConfigMap`. No Helm required.

## Files

- `configmap.yaml` — `agent_firewall.yaml` mounted at `/app/config/agent_firewall.yaml`.
  Edit this to match your tools/workflows/policy before deploying.
- `deployment.yaml` — 2 replicas, non-root, read-only root filesystem,
  `readinessProbe`/`livenessProbe` against `/readyz`/`/healthz`, resource
  requests/limits. Audit logs are written to an `emptyDir` at `/app/logs`
  (per-pod; for centralized audit, ship a `HttpBatchAuditSink`-based config
  once available, or scrape pod logs).
- `service.yaml` — `ClusterIP` service on port 8080.

## Build and push the image

```bash
docker build -t <registry>/agent-firewall:<tag> .
docker push <registry>/agent-firewall:<tag>
```

Then set `spec.template.spec.containers[0].image` in `deployment.yaml` to
`<registry>/agent-firewall:<tag>`.

## Deploy

```bash
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

## Validate manifests without a cluster

```bash
kubectl apply --dry-run=client -f configmap.yaml -f deployment.yaml -f service.yaml
```

## Updating policy

Edit `configmap.yaml`, re-apply, and roll the deployment so pods pick up the
new config (mounted ConfigMaps update on disk but the process doesn't
reload):

```bash
kubectl apply -f configmap.yaml
kubectl rollout restart deployment/agent-firewall
```

## Calling the service

From inside the cluster:

```python
from agent_firewall.client import AgentFirewallClient

client = AgentFirewallClient("http://agent-firewall.<namespace>.svc.cluster.local:8080")
decision = client.check_ingress("hello")
```

Or via plain HTTP from any language: `POST /v1/authorize`, `/v1/check-ingress`,
`/v1/check-model-request`, `/v1/authorize-tool-call`, `/v1/check-output`
(see `src/agent_firewall/server/routes.py`).
