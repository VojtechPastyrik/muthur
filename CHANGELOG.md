# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
