# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability, please report it responsibly.

Email: vojtech@pastyrik.dev

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

## Security model (summary)

- **Collector auth: mTLS, no shared tokens.** Every collector presents an
  x509 client certificate signed by the vendor intermediate CA. The brain
  rejects any cert outside the chain and enforces
  `payload.cluster_id == cert.cluster_id`, so a leaked cert cannot
  impersonate another cluster.
- **Replay protection.** Every authenticated RPC carries an
  `x-muthur-timestamp` + single-use `x-muthur-nonce` in gRPC metadata.
  Nonces are cached for 2× the accepted clock-skew window
  (`AUTH_REPLAY_WINDOW`, default 5m).
- **Runtime cert revocation.** Flipping `revoked: true` for a tenant in
  the brain's config file takes effect within ~5s without a restart
  (`TENANTS_RELOAD_INTERVAL`). A leaked leaf cert is cut off independent
  of its expiry. Hard-deleting a tenant from the config has the same
  effect.
- **PII redaction at the collector boundary.** All log lines, alert
  annotations, label names + values, and metric descriptions go through
  the redactor in `muthur-collector` before forwarding. The size guards
  fail closed — content the regex coverage cannot bound is dropped
  rather than forwarded raw.
- **Anti-prompt-injection.** Prompts are split into a `system` role
  (rules, trusted) and a `user` role (alert data, fenced with
  `<untrusted_alert_data>`). Provider APIs deliver this split natively;
  the textual fence is retained as defence in depth.
- **LLM audit log (opt-in).** `LLM_AUDIT_MODE=hash|full` emits a
  structured `audit: true` record per LLM call carrying the caller's
  verified identity (`tenant_id`, `cluster_id`, `cert_serial`),
  prompt/output hashes, and (in `full`) the bodies themselves.
- **Cost backstop.** A pathological alert storm degrades to raw
  delivery rather than running an unbounded LLM bill
  (`LLM_MAX_CALLS_PER_MINUTE`, `LLM_BURST`, `LLM_MAX_CONCURRENT`).
- **Auto-silence guard.** Critical-severity alerts are never
  auto-silenced; an optional alertname allowlist
  (`ALERTMANAGER_SILENCE_ALLOWLIST`) further restricts what the LLM may
  mute, so a prompt-injected log line cannot steer a silence onto a
  real page.
- **File-mounted secrets.** API keys and webhook URLs come from
  Kubernetes Secrets mounted as files, never plain env vars.

## In scope

- mTLS auth bypass: client cert acceptance outside the trust chain,
  cluster_id spoofing past the identity vs payload check, bootstrap
  token reuse past the SetNX single-use guard, hash-comparison side
  channels.
- Revocation latency: any path that lets a revoked tenant keep
  ingesting past the configured reload interval.
- Replay protection: nonce-cache bypass, accepted-window stretching.
- PII redaction bypass (regression to a known category) — report to
  muthur-collector if it's a redactor bug, here if it's a
  brain-side path that re-introduces unredacted data.
- Prompt injection that demonstrably overrides the system rules
  (e.g. flips severity, triggers a silence outside the allowlist,
  bypasses the structured-output validator).
- Audit log tampering / hash forgery.
- Secret leakage into logs (raw bodies, API keys, certs, bootstrap
  tokens, prompt content under `LLM_AUDIT_MODE=off`).
- Protobuf decoder issues (panic, OOM via unbounded fields).
- Notification injection (markdown / HTML / control-char in any
  receiver formatter).

## Out of scope

- Denial of service via raw alert volume — the cost backstop and the
  collector's webhook concurrency cap bound this, but a determined
  flood at the AlertManager source can still degrade enrichment.
- Compromise of the underlying Kubernetes cluster, the vendor root CA,
  or the Anthropic API.
- Vulnerabilities in upstream dependencies — report to the respective
  projects.
- Loss of audit records past the k8s container log ring buffer when
  `LLM_AUDIT_MODE=full` is enabled without an external retention sink
  (operator responsibility).
