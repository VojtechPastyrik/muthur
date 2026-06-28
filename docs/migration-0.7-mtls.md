# Migrating to v0.7 — collector mTLS

`muthur` 0.7 replaces the per-cluster bearer token with mutual TLS. The
move is intentionally a hard cut: there is no dual-accept mode, so the
brain and every collector must be upgraded together in a single
coordinated change. This document walks you through that change for a
two-cluster setup (one cluster that hosts the brain plus an in-cluster
collector, and one or more remote client clusters).

If you run more than one client cluster, repeat the client-cluster steps
in each one.

## What changes operationally

| Before (0.6.x) | After (0.7) |
| --- | --- |
| Brain authenticates collectors by `X-Collector-Token` header. | Brain requires a client certificate signed by the vendor intermediate CA. |
| Tokens delivered via `externalSecrets.collectorTokenKeys`. | One-time bootstrap token (SOPS-encrypted) used once at onboarding; renewals are pure mTLS via `/sign-csr`. |
| Cluster identity comes from the protobuf payload. | Cluster identity comes from the client cert (SAN or CN) and is cross-checked against the payload. |
| Brain listens on plain HTTP, TLS terminated at ingress. | Brain listens on HTTPS itself; ingress passes TLS through. |
| Single Helm chart `muthur`. | Same chart; a new `ca.enabled: true` switch makes it provision a self-signed root + intermediate CA on first install. |

## Prerequisites

- `cert-manager` installed in the brain cluster.
- ExternalSecrets (1Password Connect, Vault, …) or another mechanism for
  delivering encrypted secrets to client cluster GitOps repos.
- A way to share a one-time string with each client cluster operator out
  of band (Signal, 1Password Share, sealed envelope, …). The bootstrap
  token only needs to be confidential **until used**, then it's burned.

## One-time setup on the brain cluster

1. **Pre-merge generation** — for each client cluster, generate a
   bootstrap token and its SHA-256 hash:

   ```sh
   TOKEN=$(openssl rand -hex 32)
   HASH=$(printf '%s' "$TOKEN" | sha256sum | awk '{print "sha256:" $1}')
   echo "token: $TOKEN"
   echo "hash:  $HASH"
   ```

   Save the token to the secure channel you'll use to send it to the
   client cluster operator. Discard the local copy after sharing.

2. **PR the brain repo**, bumping the chart and registering tenants.
   Example for the `app-of-apps` GitOps style:

   ```yaml
   # application/muthur/muthur.yaml
   targetRevision: 0.7.0
   ```

   ```yaml
   # application/muthur/values.yaml
   ca:
     enabled: true            # provision the PKI on this cluster
   tenants:
     - clusterId: cluster-home
       tenantId: home
       bootstrapTokenHash: "sha256:<hash-for-home>"
       bootstrapExpiresAt: "2026-07-01T12:00:00Z"
       certDuration: 720h
     - clusterId: cluster-atw
       tenantId: atw
       bootstrapTokenHash: "sha256:<hash-for-atw>"
       bootstrapExpiresAt: "2026-07-01T12:00:00Z"
       certDuration: 720h
   ingress:
     tls:
       passthrough: true      # critical — see "Ingress" below
     annotations:
       traefik.ingress.kubernetes.io/router.tls: "true"
       traefik.ingress.kubernetes.io/router.tls.passthrough: "true"
   ```

   Remove the old `collectors:` block and the
   `externalSecrets.collectorTokenKeys` list.

3. **Merge** the brain PR. ArgoCD/Flux syncs:
   - cert-manager creates the root CA, the intermediate CA, and the
     brain's own server cert.
   - The brain rolls to 0.7.0, mTLS only.

4. **Back up the root CA Secret** to a safe (1Password vault, USB in a
   safe). Losing the root key means rebuilding the entire PKI and
   re-onboarding every collector.

   ```sh
   kubectl -n <muthur-ns> get secret muthur-root-ca-tls -o yaml \
     > muthur-root-ca-tls.backup.yaml
   op document create muthur-root-ca-tls.backup.yaml \
     --title "MUTHUR root CA backup"
   shred -u muthur-root-ca-tls.backup.yaml
   ```

## Per-client-cluster onboarding

Each client cluster needs:

1. **An ExternalSecret** that pulls the bootstrap token into a Kubernetes
   Secret. Example for 1Password Connect:

   ```yaml
   apiVersion: external-secrets.io/v1
   kind: ExternalSecret
   metadata:
     name: muthur-bootstrap
     namespace: monitoring
   spec:
     refreshInterval: 1h
     secretStoreRef:
       name: onepassword-store
       kind: ClusterSecretStore
     target:
       name: muthur-bootstrap
     data:
       - secretKey: token
         remoteRef:
           key: muthur-collector
           property: bootstrap-token
   ```

2. **The collector chart** at 0.3 with mTLS values. (See the matching
   migration doc in the `muthur-collector` repo for the full set of
   values.)

3. **Merge** the client PR. The collector's init container reads the
   bootstrap token, calls `https://<brain>/bootstrap-cert`, receives a
   leaf cert plus the intermediate chain, and writes them to the
   `muthur-collector-tls` Secret. The main container starts mTLS-only.

4. **Verify** in the brain logs:

   ```
   bootstrap issued cluster_id=cluster-atw tenant_id=atw cert_duration=720h
   ```

## Day-2 operations

### Renewals
The collector's renew CronJob calls `/sign-csr` over the existing mTLS
connection roughly every `certDuration` − 7 days. The brain signs the
new CSR using the same intermediate and returns the leaf. The
collector's running process picks up the rotated cert via fsnotify
without a restart. **No operator action.**

### Revoking a collector
Open a PR to your brain repo:

```yaml
tenants:
  - clusterId: cluster-acme
    revoked: true
```

After merge, the brain will refuse `/sign-csr` for that cluster
immediately. The existing leaf cert keeps working for `/ingest` until
natural expiry. Pair with a deny-list change on `/ingest` if you need
cutoff sooner.

### Rotating a bootstrap token
Open a PR with a new `bootstrapTokenHash` and `bootstrapExpiresAt`. The
old hash stops working immediately on sync. Share the new token with
the client operator out of band.

### Recovering a lost intermediate
If the intermediate Secret is deleted, cert-manager will mint a new one
from the same root. Brain pods may crashloop until the new intermediate
is available; once it is, the next renewal each collector performs will
move them to leaves signed by the new intermediate. No client-side
action is required.

### Recovering a lost root
Restore the Secret from your safe backup with `kubectl apply -f`. If you
have no backup, the only path forward is to flip `ca.enabled: false`,
delete the chart-managed resources, re-enable, and re-onboard every
collector with a fresh bootstrap token. Do not lose the root.

## Ingress: TLS passthrough is mandatory

mTLS only works end-to-end if the ingress does **not** terminate TLS.
The brain has to see the raw client cert, which means the ingress must
pass the TLS bytes through unmodified.

For Traefik, the annotations above are enough. For Envoy Gateway, set
the `Listener` to `TLS_PASSTHROUGH`. For NGINX, use
`nginx.ingress.kubernetes.io/ssl-passthrough: "true"`.

The brain's own server cert is issued from the vendor intermediate, so
clients verify the brain too — the chain is closed at both ends.

## What didn't survive the cut

- The `X-Collector-Token` header and any tooling that injected it.
- Static, never-rotated per-cluster shared secrets stored in
  ExternalSecrets / Vault. Use bootstrap tokens (one-shot, expiring)
  instead.
- ArgoCD applications that wired `collector-token-*` Vault keys —
  delete them.

If you still have collectors on a version that uses tokens after the
brain upgrade, they will receive `401 unauthorized` on every alert
until you upgrade them. Plan the merge windows accordingly.
