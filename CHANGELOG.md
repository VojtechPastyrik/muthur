# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.4] — 2026-06-29

### Added

- **Grafana dashboard JSON** at `helm/muthur/grafana/dashboard.json`.
  Templated by the `cluster_id` label (so a multi-tenant deployment is
  one dashboard, not N), covers alert flow, LLM cost + latency + reliability,
  silence outcomes (incl. the new `low_confidence` bucket), notifications,
  incidents, operator feedback, and the collector's enrichment +
  redaction surface. Companion `README.md` documents import + a $ math
  snippet for cost reporting.

- **Auto-tier on low LLM confidence.** When the model returns
  `confidence: low` and asks for an auto-silence, the silence is now
  refused (the alert still reaches on-call so a human can verify) and
  the outcome is counted as
  `muthur_silences_total{result="low_confidence"}`. A chronically
  uncertain model is now visible as a metric rather than silently
  muting pages.
- **Per-tenant LLM cost backstop.** `llmlimit.Pool` gives every
  `cluster_id` its own rate + concurrency bucket, lazily allocated
  on first use. One noisy collector can no longer drain the LLM
  budget for the others; saturation in one tenant cannot starve
  another. Pool sizes use the same env knobs as before
  (`LLM_MAX_CALLS_PER_MINUTE`, `LLM_BURST`, `LLM_MAX_CONCURRENT`)
  applied per-tenant.
- **Per-tenant LLM metrics.** `LLMCalls`, `LLMTokens`,
  `LLMCallDuration`, `LLMValidationFailures`, `LLMRetries`,
  `LLMDegraded`, and `LLMThrottled` all carry a `cluster_id` label.
  Operators can now build per-tenant cost + reliability panels in
  Grafana (multiply tokens by provider $/token).

### Changed

- `Limiter.Acquire` / `Release` take a `clusterID` argument so the
  metric label is correctly attributed. Existing call sites are
  migrated; tests updated.
- `BACKLOG.md` was substantially out of date and has been refreshed
  to mark EPIC 1 (gRPC), EPIC 2 (mTLS + CA + revocation + replay),
  the v0.8.2 audit + redaction work, and EPIC 9 auto-tier / cost
  backstop as shipped with their delivering versions. A "current
  state" header preserves the original 2026-06-28 mapping for
  reference.

## [0.8.3] — 2026-06-29

### Added

- `TENANTS_RELOAD_INTERVAL` env (default `5s`, exposed via
  `config.tenantsReloadInterval` in the chart). Lets operators tune how
  often the brain stat-polls the tenants config for an mtime change —
  shorter propagates a revoke faster, longer reduces syscall churn.
- `values.schema.json` now validates `config.llm.auditMode` as an enum of
  `off | hash | full` so a typo is caught at `helm install`/`upgrade`
  rather than at runtime via a silent fallback to `off`.
- `LLM_AUDIT_MODE` added to `.env.example` for parity with the chart.

### Fixed

- `docs/migration-0.7-mtls.md` stray text on the title line.

## [0.8.2] — 2026-06-29

### Added

- **Runtime cert revocation.** A new gRPC interceptor rejects requests from
  any verified tenant whose entry has `revoked: true` (or has been hard-
  deleted from the config). Before this, the `revoked` flag only blocked
  re-issuance — a leaked leaf cert stayed usable until expiry. Combined
  with hot-reload below, a flag-flip takes effect within ~5s and no brain
  restart is needed.
- **Tenants config hot-reload.** The brain now stat-polls `MUTHUR_CONFIG_FILE`
  every 5s and atomically swaps the in-memory tenant snapshot when the file
  mtime advances. Mirrors the existing TLS cert reloader pattern; no
  fsnotify dependency. A torn write or bad YAML keeps the previous snapshot
  serving, so a mid-update ConfigMap cannot lock every collector out.
- **Structural anti-prompt-injection.** The Anthropic and OpenAI-compatible
  providers now split the prompt into a `system` role (analysis rules,
  trusted, vendor-authored) and a `user` role (alert data, fenced with
  `<untrusted_alert_data>`, attacker-influencible). The textual fence is
  retained as defence-in-depth. Attacker-controlled log lines reach the
  model in the user role, which the instruction-hierarchy training weighs
  below the system role.
- **`LLM_AUDIT_MODE` (default `off`).** Per-call audit log of LLM input /
  output with three modes: `off` (no audit), `hash` (identity + SHA-256 of
  the system prompt, user prompt and output — proves a call happened
  without inflating logs), `full` (identity + hashes + bodies, intended
  for deployments with an external retention sink). `off` is the default
  so a stacktrace-heavy alert storm does not eat the k8s container log
  ring buffer.

### Changed

- `RevocationInterceptor` runs between `AuthInterceptor` and
  `ReplayInterceptor`. `BootstrapCert` remains exempt (no identity in
  context yet — the bootstrap handler keeps its own revoked check).
- `auth.BootstrapHandler` and `auth.RenewHandler` now take a
  `TenantsProvider` instead of a `*Tenants`. Static deployments can wrap
  their fixed snapshot with `auth.StaticTenants{T: ...}`.

## [0.8.1] — 2026-06-28

### Fixed

- mTLS trust pool now includes the vendor intermediate CA. The 0.8.0
  release loaded only the root cert into ClientCAs, so leaves signed by
  the intermediate (which is what bootstrap/renew issues) had no chain
  to walk back to the root. The previous REST listener tolerated this;
  the stricter gRPC handshake surfaced it as `tls: unknown certificate
  authority`. Collectors on 0.8.0 no longer need a chart bump — only
  the brain image moves.

## [0.8.0] — 2026-06-28

### Changed

- **Breaking wire format.** The mTLS listener (port 8080) now serves the
  gRPC `monitoring.v1.Brain` service instead of the previous REST
  endpoints (`/ingest`, `/bootstrap-cert`, `/sign-csr`). Collectors must
  upgrade in lockstep — `muthur-collector` ≥ 0.8.0 is required. The
  public listener (port 8081, `/feedback`, `/healthz`, `/metrics`) is
  unchanged.
- Replay protection (timestamp + nonce) now travels via gRPC metadata
  (`x-muthur-timestamp`, `x-muthur-nonce`) instead of HTTP headers
  (`X-Muthur-*`). Same single-use semantics; same identity-scoped nonce
  cache.
- Ingress passthrough is wire-format-agnostic: existing Traefik
  IngressRouteTCP / Gateway API TLSRoute / nginx ssl-passthrough configs
  keep working without changes (TCP passthrough doesn't inspect the
  payload).

### Added

- gRPC reflection on the mTLS listener so operators can `grpcurl` the
  Brain service in production. Reflection only exposes the schema, which
  is already public in the proto.

### Migration

- Bump both charts to 0.8.0 at the same time. There is no compatibility
  shim for mixed REST/gRPC fleets.
- `CENTRAL_AGENT_URL` on the collector can stay as `https://muthur-api…`
  (the scheme is stripped automatically) or be set to a bare `host:port`.

## [0.7.6] — 2026-06-28

### Fixed

- Server cert SAN now picks the public hostname from whichever ingress
  flavor is enabled (`ingress.host`, `ingressRouteTCP.host`, or
  `tlsRoute.host`). 0.7.5 only looked at `ingress.host`, so operators
  who disabled standard Ingress in favor of IngressRouteTCP ended up
  with a cert whose SAN defaulted to the placeholder
  `muthur.yourdomain.com`, breaking collector verification with
  `x509: certificate is valid for muthur.yourdomain.com, …, not
  muthur-api.pastyrik.dev`.

## [0.7.5] — 2026-06-28

### Added

- Multiple ingress flavors for mTLS passthrough. Pick the one that
  matches your cluster's ingress stack:
  - **Traefik:** `ingressRouteTCP.enabled: true` (HostSNI matching +
    tls.passthrough). Required for v2/v3 — standard Ingress annotations
    silently terminate with the Traefik default cert.
  - **Gateway API (Envoy Gateway / Cilium / …):** `tlsRoute.enabled: true`.
    Pair with a Gateway whose listener has tls.mode=Passthrough.
  - **NGINX Ingress:** keep `ingress.enabled: true` and add
    `nginx.ingress.kubernetes.io/ssl-passthrough: "true"` to
    ingress.annotations. The controller must be started with
    `--enable-ssl-passthrough`.

## [0.7.4] — 2026-06-28

### Changed

- `config.publicUrl` is now optional. When unset, the deployment template
  derives `MUTHUR_PUBLIC_URL` from `publicIngress.host` (with the right
  scheme based on `publicIngress.tls.enabled`). Cuts the duplicate
  hostname out of values without changing brain behaviour. Operators can
  still override by setting `config.publicUrl` explicitly.

## [0.7.3] — 2026-06-28

### Added

- **Dual-listener brain.** A second router serves `/feedback`, `/metrics`,
  and `/healthz` as plain HTTP on a separate port (`PUBLIC_PORT`, default
  `8081`). The mTLS listener on `PORT` keeps owning the collector
  endpoints. This unblocks the browser-clickable feedback link from
  notifications: the public-facing ingress can terminate TLS with a
  browser-trusted CA (Let's Encrypt, Cloudflare) without colliding with
  the mTLS passthrough on the API port.
- New chart values: `service.publicPort` (default `8081`) and
  `publicIngress` block. Set `publicIngress.enabled: true` and supply a
  hostname to expose `/feedback` on a browser-friendly DNS name.
- Kubelet probes now hit the plain-HTTP listener, so they no longer need
  to wrestle with the mTLS handshake.

### Changed

- Service exposes both ports (`https` 8080, `http` 8081) so internal
  consumers (Prometheus ServiceMonitor, /feedback within-cluster) pick
  the right one by name.

## [0.7.2] — 2026-06-28

### Fixed

- Add `fsGroup: 65532` to the brain pod's security context. cert-manager
  writes Secret data with `root:root` ownership and the chart mounts cert
  files at mode `0400`; without `fsGroup` the non-root container (uid
  65532) hits `permission denied: /secrets/tls/server/tls.crt` and the
  TLS listener fails to start. `fsGroup` triggers kubelet to chgrp the
  mounted files so the brain user can read them.

## [0.7.1] — 2026-06-28

### Fixed

- `muthur-intermediate` is now a namespaced `Issuer` rather than a
  `ClusterIssuer`. The previous form failed at install time because
  cert-manager's default `--cluster-resource-namespace` (`cert-manager`)
  does not match the release namespace where the intermediate CA Secret
  actually lives, leaving the brain's own server cert stuck on
  `ErrInitIssuer: secrets "muthur-intermediate-ca-tls" not found`.
  Out-of-cluster collectors do not need the issuer — they exchange
  CSRs via `/bootstrap-cert` and `/sign-csr` instead.

## [0.7.0] — 2026-06-28

Theme: collector authentication is now mutual TLS. The shared per-cluster
bearer token (`X-Collector-Token`) is gone.

### Added

- **mTLS listener** on the brain. Identity is taken from the verified
  client certificate's SPIFFE URI SAN
  (`spiffe://muthur/<tenant>/<cluster>`) or its Common Name. The brain's
  own server cert is sourced through a `GetCertificate` callback that
  reloads on file-mtime change, so cert-manager rotations require no
  restart.
- **`/bootstrap-cert` endpoint.** A first-time collector posts the
  one-time bootstrap token shared at onboarding plus a freshly generated
  CSR; the brain validates the token, signs the CSR with the vendor
  intermediate, and returns the leaf plus the CA chain. Tokens are
  single-use, enforced atomically via the existing store.
- **`/sign-csr` endpoint.** Day-2 path for collectors that already hold
  a valid cert. Authenticated by mTLS, replay-protected, and refuses
  revoked tenants.
- **Replay protection** on every authenticated request:
  `X-Muthur-Timestamp` plus a 128-bit hex `X-Muthur-Nonce`, scoped per
  identity and stored in the shared store with TTL = 2 × window
  (default 5 m).
- **Identity binding** on `/ingest`: payload `cluster_id` must equal the
  cert's `cluster_id`, else 403.
- **Two-tier CA in the Helm chart** (cert-manager): self-signed root
  (10 y) → intermediate (1 y) → leaves. The brain mounts the
  intermediate to sign collector CSRs. The root Secret is pinned with
  `helm.sh/resource-policy=keep` and ArgoCD `Prune=false` so neither
  uninstall nor sync can wipe the PKI.
- **`tenants:` block** in the chart values + `muthur.yaml` ConfigMap.
  Adding, revoking, or rotating a tenant is now a regular GitOps PR.
- New environment variables: `TLS_SERVER_CERT_FILE`,
  `TLS_SERVER_KEY_FILE`, `TLS_TRUST_ROOT_FILE`, `INTERMEDIATE_CA_FILE`,
  `INTERMEDIATE_KEY_FILE`, `AUTH_REPLAY_WINDOW`.

### Changed

- The brain listener serves HTTPS exclusively. Liveness and readiness
  probes use `scheme: HTTPS`. The `Service` `targetPort` is renamed to
  `https`.
- `helm/muthur/templates/ingress.yaml` exposes a `tls.passthrough`
  toggle. When mTLS is in use the ingress MUST pass TLS through; the
  client cert is verified at the brain, not at the ingress.

### Removed (BREAKING)

- `X-Collector-Token` header on `/ingest`. The brain refuses requests
  without a verified client cert.
- `COLLECTOR_TOKEN`, `COLLECTOR_TOKENS`, and `COLLECTOR_TOKEN_*` env
  vars.
- Chart values `collectors[]`, `externalSecrets.collectorTokenKeys`,
  and `devSecrets.collectorTokens`.
- `config.CollectorConfig` and `Config.CollectorTokenMap` from the Go
  config package.

### Migration

A coordinated brain + every collector merge is required. See
[docs/migration-0.7-mtls.md](docs/migration-0.7-mtls.md). There is no
dual-accept mode in this release — collectors that still post a token
will be rejected as soon as the brain rolls to 0.7.0.

## [0.6.0]

- Multi-provider LLM support: Anthropic (default) and OpenAI-compatible
  backends, with a validate-retry-degrade loop guaranteeing structured
  output even when a weaker model returns malformed JSON.

(See git history for releases prior to this changelog.)
