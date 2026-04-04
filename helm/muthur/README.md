# muthur Helm Chart

Helm chart for deploying `muthur`, an AI-powered Kubernetes monitoring server.

`muthur` receives enriched alerts from `muthur-collector` instances, evaluates alerts with Anthropic Claude, deduplicates repeated events, and sends notifications based on routing rules.

## Prerequisites

- Kubernetes `>= 1.24`
- Helm `>= 3.10`
- A secret backing your notification/API credentials (External Secrets or dev-only inline values)

## Install

```bash
helm repo add vojtechpastyrik https://vojtechpastyrik.github.io/charts
helm repo update

helm install muthur vojtechpastyrik/muthur \
  --namespace muthur \
  --create-namespace
```

## Upgrade

```bash
helm upgrade muthur vojtechpastyrik/muthur --namespace muthur
```

## Uninstall

```bash
helm uninstall muthur --namespace muthur
```

## Important Values

| Key | Type | Default | Description |
|---|---|---|---|
| `image.repository` | string | `ghcr.io/vojtechpastyrik/muthur` | Container image repository |
| `image.tag` | string | `""` | Image tag (uses chart appVersion when empty) |
| `service.port` | int | `8080` | Service port |
| `ingress.enabled` | bool | `true` | Enable Ingress |
| `ingress.host` | string | `muthur.yourdomain.com` | Ingress hostname |
| `httpRoute.enabled` | bool | `false` | Enable Gateway API HTTPRoute |
| `gateway.enabled` | bool | `false` | Create a Gateway with TLS cert reference |
| `ingressRoute.enabled` | bool | `false` | Enable Traefik IngressRoute |
| `config.anthropicModel` | string | `claude-opus-4-5` | Claude model used for evaluation |
| `config.grafanaBaseUrl` | string | `https://grafana.yourdomain.com` | Grafana base URL used in deep links |
| `config.alertmanagerUrl` | string | `http://alertmanager.monitoring.svc:9093` | Alertmanager API URL |
| `config.alertmanagerSilenceEnabled` | bool | `false` | Enable automatic silence creation |
| `receivers` | list | `[]` | Named notification receivers (see below) |
| `routing.rules` | list | `[]` | First-match routing rules mapping alerts to receivers |
| `collectors` | list | `[]` | Allowed collectors and token key mapping |
| `externalSecrets.enabled` | bool | `true` | Read secrets from External Secrets Operator |
| `externalSecrets.receiverSecretKeys` | list | `[]` | Secret keys to fetch for receivers; mounted at `/secrets/receivers/<key>` |
| `devSecrets.enabled` | bool | `false` | Create inline dev secret (not for production) |
| `devSecrets.receiverSecrets` | map | `{}` | Inline receiver credentials for local dev |

## Receivers and Routing

muthur uses an AlertManager-style receiver model: you define named receivers and routing rules reference them by name. You can have **multiple receivers of the same type** — e.g. one Discord webhook for the ops team and another for the dev team.

Each receiver has two sections:

- **`config`** — literal non-sensitive fields (e.g. `chat_id` for Telegram)
- **`secretKeys`** — map of field name → Secret key name. The chart mounts the Secret value as a file at `/secrets/receivers/<key>`, and muthur reads the file contents at runtime.

Sensitive values never appear as environment variables and never show up in `ps`, `/proc`, or crash dumps.

### Supported receiver types

| Type | Required fields | Optional fields |
|---|---|---|
| `telegram` | `token`, `chat_id` | — |
| `discord` | `webhook_url` | — |
| `slack` | `webhook_url` | — |
| `pagerduty` | `routing_key` | `url` (defaults to `events.pagerduty.com`) |
| `webhook` | `url` | — |

Any field can go under either `config` (literal) or `secretKeys` (mounted from Secret). Typically tokens, webhook URLs, and routing keys are secrets; chat IDs and custom URLs are literals.

### Full example

```yaml
receivers:
  - name: ops-telegram
    type: telegram
    config:
      chat_id: "-100123456789"
    secretKeys:
      token: ops-telegram-token

  - name: critical-discord
    type: discord
    secretKeys:
      webhook_url: critical-discord-webhook

  - name: dev-discord
    type: discord
    secretKeys:
      webhook_url: dev-discord-webhook

  - name: oncall-pd
    type: pagerduty
    secretKeys:
      routing_key: oncall-pagerduty-key

  - name: audit-slack
    type: slack
    secretKeys:
      webhook_url: audit-slack-webhook

routing:
  rules:
    - name: prod-critical
      match:
        severity: critical
        cluster_id: cluster-prod
      receivers: [ops-telegram, critical-discord, oncall-pd]

    - name: dev-warnings
      match:
        severity: warning
        cluster_id: cluster-dev
      receivers: [dev-discord]

    - name: audit-everything
      match: {}
      receivers: [audit-slack]
```

Match fields: `severity`, `cluster_id`, `alert_name`, `namespace`. Empty match fields match anything. First matching rule wins.

## Secrets and Credentials

Two modes are supported:

1. **Production (recommended):** `externalSecrets.enabled=true`
   - Chart creates an `ExternalSecret` that syncs from `externalSecrets.remoteSecretPath`.
   - `collectors[*].tokenSecretKey` defines collector tokens.
   - `externalSecrets.receiverSecretKeys` lists the Secret keys that feed receivers.
2. **Development only:** `devSecrets.enabled=true`
   - `devSecrets.receiverSecrets` is an inline key → value map rendered into a Kubernetes Secret.

All Secret keys referenced by `receivers[*].secretKeys` must exist in one of these sources.

### Production secret example

```yaml
collectors:
  - clusterId: cluster-prod
    tokenSecretKey: collector-token-prod

externalSecrets:
  enabled: true
  secretStoreName: vault-backend
  remoteSecretPath: muthur/prod
  collectorTokenKeys:
    - collector-token-prod
  receiverSecretKeys:
    - ops-telegram-token
    - critical-discord-webhook
    - dev-discord-webhook
    - oncall-pagerduty-key
    - audit-slack-webhook
```

### Dev secret example

```yaml
devSecrets:
  enabled: true
  anthropicApiKey: "sk-ant-..."
  collectorTokens:
    - clusterId: cluster-dev
      token: "dev-token"
  receiverSecrets:
    ops-telegram-token: "123:abc"
    critical-discord-webhook: "https://discord.com/api/webhooks/..."
```

## How it works under the hood

1. Helm renders each receiver into the ConfigMap. For every `secretKeys[field] = key`, it writes `<field>_file: /secrets/receivers/<key>` into the receiver config.
2. Helm creates (or syncs) a Kubernetes Secret and mounts it as a volume at `/secrets/receivers/`, one file per key.
3. At startup, muthur reads the ConfigMap, sees the `_file` suffix, reads the file contents, and uses them as the real field value.

This means secrets never become environment variables, and rotating a Secret value (with a sidecar reloader or pod restart) updates the receivers without rebuilding anything.

## Exposure Options

Expose the service via one (or more) of:

- `Ingress` (`ingress.enabled=true`)
- Gateway API `HTTPRoute` (`httpRoute.enabled=true`) with optional managed `Gateway` (`gateway.enabled=true`)
- Traefik `IngressRoute` (`ingressRoute.enabled=true`)

### HTTPRoute + Gateway example

```yaml
httpRoute:
  enabled: true
  host: muthur.example.com
  parentRefs:
    - name: muthur
      namespace: muthur

gateway:
  enabled: true
  className: traefik
  name: muthur
  namespace: muthur
  tls:
    enabled: true
    secretName: muthur-tls
```

### Traefik IngressRoute example

```yaml
ingressRoute:
  enabled: true
  host: muthur.example.com
  entryPoints: [websecure]
  tls:
    enabled: true
    secretName: muthur-tls
```

## Source and Support

- Source: https://github.com/VojtechPastyrik/muthur
- Issues: https://github.com/VojtechPastyrik/muthur/issues
