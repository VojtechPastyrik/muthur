# muthur-central

Central AI monitoring agent for Kubernetes. Part of the [muthur](https://github.com/VojtechPastyrik) system, named after MU/TH/UR 6000 from Alien.

Receives enriched alert payloads from [muthur-collector](https://github.com/VojtechPastyrik/muthur-collector) instances, evaluates them with Claude, deduplicates, and routes notifications.

```
Cluster A              Cluster B              Cluster C
muthur-collector       muthur-collector       muthur-collector
     |                      |                      |
     +----------+-----------+----------+-----------+
                |                      |
                v                      v
             muthur-central (home cluster)
               POST /ingest
               Claude evaluation
               Routing + Notifications
```

## Prerequisites

- Go 1.26+
- protoc + protoc-gen-go
- Helm 3
- Anthropic API key

## Quick start

```bash
# Generate protobuf
make proto

# Run locally
cp .env.example .env
# Edit .env with your Anthropic API key and collector tokens
make dev

# Run tests
make test

# Build Docker image
make docker
```

## Deploy via Helm

```bash
helm repo add vojtechpastyrik https://vojtechpastyrik.github.io/charts
helm repo update

helm install muthur-central vojtechpastyrik/muthur-central \
  --namespace muthur --create-namespace \
  --set config.grafanaBaseUrl=https://grafana.yourdomain.com
```

## Notification channels

Telegram, Discord, Slack, PagerDuty, generic webhook. Disabled when required env is empty.

## Routing

Configured via `routing.rules` in values.yaml. First matching rule wins. Match on severity, cluster_id, alert_name, namespace.

## License

MIT
