# Grafana dashboard

`dashboard.json` is the canonical operator dashboard for MUTHUR. It covers
both the brain and the collector and is templated by the `cluster_id`
label that every LLM-related metric now carries (v0.8.4+), so a single
dashboard handles a multi-tenant deployment.

## Sections

- **Alert flow** — receive rate, dedup suppression, pipeline in-flight.
- **LLM cost & latency** — tokens per tenant per direction, call rate by
  result, p50/p95 call duration, per-tenant throttle hits.
- **LLM reliability & cache** — schema validation failures, corrective
  retries, degraded-to-raw events, cache hit rate.
- **Silences & notifications** — auto-silence outcomes
  (`created` / `blocked` / `error` / `low_confidence` since v0.8.4),
  delivery success per receiver.
- **Incidents & feedback** — incident rate by correlated-group size,
  operator verdict mix (useful / wrong).
- **Collector** — forwards, enrichment p95 latency per source,
  redaction replacements per surface, fail-closed drops per reason,
  webhook-side concurrency drops.

## Import

The dashboard ships as plain JSON and is not wired into the Helm chart
on purpose — operators tend to keep dashboards under their own Grafana
provisioning so an `argocd app sync` does not stomp local tweaks.

To import manually:

1. In Grafana → **Dashboards → Import**.
2. Upload `dashboard.json` (or paste it).
3. Pick the Prometheus datasource that scrapes the brain and collector
   `/metrics` endpoints.
4. The `cluster_id` selector at the top defaults to "All"; pick a single
   tenant for a per-tenant cost / reliability view.

To wire into a sidecar-discovery Grafana (e.g.
`grafana-operator` or the `grafana.dashboardSelector` mechanism),
package this file in a `ConfigMap` with the label your Grafana watches
(commonly `grafana_dashboard: "1"`).

## Cost view ($)

The dashboard plots **tokens per second**, not dollars. Multiply by the
per-million-token rate of your provider to get a $ figure:

```promql
# Anthropic Claude Opus 4.5 example (replace with your contract rate)
# input: $15 / M tokens, output: $75 / M tokens
sum by (cluster_id) (
  increase(muthur_llm_tokens_total{direction="input",cluster_id=~"$cluster_id"}[24h]) * 15  / 1e6 +
  increase(muthur_llm_tokens_total{direction="output",cluster_id=~"$cluster_id"}[24h]) * 75 / 1e6
)
```

Add as a custom panel if you want a $ chart per tenant.
