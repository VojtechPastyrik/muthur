# MUTHUR backlog

Strategic feature backlog. Short bullets, what — not how.

Positioning anchor: **AI layer over existing Prometheus/AlertManager. Not a replacement.**
North star: thin, privacy-first AI brain for vendors managing client clusters.

**Status legend:** ✅ done · 🟡 partial / exists but limited · ❌ not started · 🚫 dropped/deferred

---

## Findings from EPIC 0 mapping (2026-06-28)

Key surprises after reading both repos:

1. **"Signed protobuf" in original plan DOES NOT exist.** Wire format is plain protobuf, auth is bearer token (`X-Collector-Token` header). No HMAC, no signature, no replay protection. Update Tier 1 plans accordingly.
2. **Zero TLS / mTLS anywhere.** No `crypto/tls` usage in either repo. Forwarder uses default `http.Client`. EPIC 2 is fully greenfield.
3. **Trust calibration (EPIC 9) is ~70% already in place.** `Analysis.Confidence` and `Analysis.Grounding` fields already exist in the schema. Validate-retry-degrade loop ships. Feedback loop (verdict storage, few-shot replay) exists. Remaining work is mostly per-tenant cost backstop + auto-tier degradation policy + "why this severity" free-text.
4. **Redaction (EPIC 7 base) is solid and fail-closed.** Size guards mandatory, custom patterns supported. Missing: brain-side audit/proof report, local LLM first-class polish, air-gapped mode flag.
5. **Per-tenant isolation is partial.** Token-to-cluster mapping enforces identity, but Redis prefix is global, LLM cost budget is global, no per-tenant rate limit. Multi-tenant vendor mode needs work.
6. **Proto files are duplicated, not symlinked.** `proto/alert.proto` exists in both repos as independent copies. Risk of silent drift on schema changes.
7. **Loki + Prometheus clients are ad-hoc, no common interface.** Confirms EPIC 4A is needed before adding Tempo/ELK/OTel.

---

## Next milestone — Tier 1 (active)

Goal: take MUTHUR from "works" to "trust-worthy for production with paying clients."

Order:
1. **EPIC 0** — mapping ✅ (this section + Explore output, can be promoted to `ARCHITECTURE.md`)
2. **EPIC 2** — mTLS + vendor CA (biggest piece, ~60% of Tier 1 time, blocks serious deployment)
3. **EPIC 9** — trust calibration finalization (~30% remaining — per-tenant cost + auto-tier policy)
4. **EPIC 7** — privacy story polish (local LLM first-class + air-gapped + audit report)

Revised estimate after mapping: **~6-8 weeks solo** (less than the original 2-3 months because EPIC 9 is mostly done and EPIC 7 has a solid base).

Everything else is deferred until Tier 1 ships. Resist scope creep.

---

## EPIC 0 — Mapping (before any code) — ✅ DONE
- ✅ Architecture mapped (`Findings from EPIC 0 mapping` section above; full output available in conversation)
- ❌ Promote findings to `ARCHITECTURE.md` in repo (one-pager, link to Explore output)
- ✅ Auth flow documented (token in `X-Collector-Token` header, no signed proto)
- ✅ Verified collector is outbound-only (no inbound handler, no listening port for brain)
- ✅ LLM loop documented (provider abstraction at `internal/evaluator/`, validate-retry-degrade in `analyzer.go:169-221`)
- ✅ Redaction documented (`internal/redact/redactor.go`, fail-closed, size guards mandatory)

## EPIC 1 — Transport: collector-initiated bidi gRPC stream — ❌
- ❌ Replace POST `/ingest` with bidirectional gRPC stream (collector dial → brain)
- ❌ Long-poll fallback for environments blocking gRPC
- ❌ Backpressure + auto-reconnect after disconnect
- ✅ No new inbound port on collector (already outbound-only)
- ❌ Unify proto into a single source of truth (currently duplicated in both repos) — do BEFORE this epic
- ❌ `make proto` + tests for the new stream

## EPIC 2 — Auth (mTLS + CA + per-tenant) — ❌ greenfield
- ❌ **Replace `X-Collector-Token` bearer token with mTLS + vendor CA**
- ❌ Root CA offline, intermediate file-mount on brain
- ❌ Brain trusts a single root (vendor), verifies offline
- ❌ Identity from cert (SAN/CN), never from payload
- ❌ cert-manager in client cluster: local key generation
- ❌ CSR signing via vendor intermediate (root never leaves vendor)
- ❌ Auto rotation (`duration` + `renewBefore`)
- ❌ Revocation by drop from brain trust (no client-side intervention)
- ❌ Per-tenant rate limit + concurrency (today: global `llmlimit`, no per-cluster bucket)
- 🟡 Authz: `identity.cluster_id == payload.cluster_id`, else 403 (today: token-cluster mapping exists, needs cert-based replacement)
- ❌ Replay protection: timestamp + nonce + cache (today: none — relying on TLS at the ingress)
- ❌ Per-tenant Redis prefix (today: shared `muthur:` prefix → cross-tenant data lives in same namespace)
- ❌ Migration: dual-accept (token+mTLS) for N versions, then drop

## EPIC 3 — Agentic pull — ❌
- ❌ LLM loop: model can request more logs/metrics mid-analysis
- ❌ Brain → collector over existing stream (depends on EPIC 1)
- ❌ Pulled data goes through same fail-closed redaction (collector redactor is ready)
- ❌ Max N pulls per incident (cost backstop)
- ❌ Pull respects per-tenant authz (depends on EPIC 2 authz being cert-based)
- ❌ Works for any OpenAI-compatible backend, not just Claude (provider abstraction exists ✅)
- ❌ Audit log of every pull (what model asked, what it got)

## EPIC 4 — Sources (abstraction + new) — 🟡
- ❌ **EPIC 4A:** Unify Loki/Prometheus into a single "enrichment source" interface (today: ad-hoc clients in `internal/loki/`, `internal/prometheus/`)
- ❌ **EPIC 4B:** Tempo/Jaeger traces — trace ID correlation, error span into analysis
- ❌ **EPIC 4C:** Elasticsearch/OpenSearch logs (Loki alternative)
- ❌ **EPIC 4D:** OpenTelemetry direct ingest (signals without middleware)
- ✅ Same fail-closed redaction on every source (Redactor is monolithic; new sources just pipe through it)
- ✅ Helm values + secrets per source consistent (existing Loki/Prom pattern is reusable)

## EPIC 5 — Remediation as GitOps  *(🚫 DEFERRED — risk of breaking positioning)*
**Decision (2026-06-28):** do not implement preemptively. Would push MUTHUR into "automation tool" territory, away from "alert brain". Existing solutions (Robusta, GitOps controllers) cover this. Reconsider only if multiple paying clients explicitly request it AND we are sure the trust model holds (no write access from brain into client clusters).
- ~~Suggested change as PR into manifests repo, not kubectl~~
- ~~No write/mutate access from brain into clusters~~
- ~~Default read-only / advisory~~
- ~~Audit each suggestion as structured log~~

## EPIC 6 — On-call workflow  *(🚫 DROPPED — competes with PagerDuty/Grafana OnCall)*
**Decision (2026-06-28):** dropped. MUTHUR forwards to PagerDuty / Grafana OnCall; they handle rotation. Reimplementing rotation/escalation = competing badly with mature tools. Feature, not gap: "MUTHUR is the brain, not the pager."
- ~~Escalate after X minutes without "useful" feedback~~
- ~~Schedule (on-call rota)~~

## EPIC 7 — Privacy / data sovereignty (sales argument) — 🟡
- ❌ **Local embedder** (no cloud embedding calls)
- 🟡 **Local LLM** first-class (provider abstraction supports OpenAI-compatible → Ollama/vLLM work today; need: prompt tuning for smaller models, validated examples in docs, recommended models per task)
- ❌ **"Air-gapped mode"** flag — no egress except brain (refuse to start with cloud LLM provider config when set)
- 🟡 **Audit / proof report** — what actually left the cluster
  - ✅ Collector tracks redaction stats (`TotalLogLines`, `RedactedLogLines`, `TotalReplacements` + per-category counts when `REDACT_LOG_STATS=true`)
  - ❌ Brain surfaces it (today it's opaque in payload, never logged or shown in notifications)
  - ❌ Per-tenant exportable audit log
- 🟡 **Configurable PII obfuscation** — exists for credentials/PII/PCI/network patterns, supports `REDACT_EXTRA_PATTERNS` custom regex. Missing: field-level masks for structured payload (labels, annotations)

## EPIC 8 — MUTHUR observability — 🟡
- 🟡 Prometheus metrics (✅ exist: `LLMTokens`, `LLMRetries`, `LLMDegraded`, `LLMValidationFailures`, redaction stats — ❌ not per-tenant labeled)
- ❌ Ship Grafana dashboard (JSON in repo, no custom UI)
- ❌ OpenTelemetry traces brain → LLM → notifier
- 🟡 Cost report (LLM tokens, $) per tenant (✅ token counter exists; ❌ no $ math, no per-tenant labels)
- ✅ "Incident recurrence" (exists via deterministic alertkey + `IncidentHistory` store)

## EPIC 9 — Trust calibration for LLM output — 🟡 (most plumbing already exists)
- ✅ **Confidence score per analysis** (`Analysis.Confidence` field exists: "high"/"medium"/"low" — emitted in notifications)
- 🟡 **"Why this severity" rationale** (`Analysis.Grounding` field exists: "stated"/"inferred"; ❌ no free-text rationale yet)
- ✅ **Feedback loop: human label "useful/wrong"** (`/feedback?id=&verdict=` endpoint + Redis-backed verdict store, 30d TTL)
- ✅ **Prompt tuning via few-shot replay** (recent verdicts replayed as `Example`s in next prompt)
- ❌ **Auto-tier:** low confidence → ship raw + LLM summary (today: degrade only happens on hard validation failure, not on low confidence)
- 🟡 **Cost backstop:** hard limit $ per incident, per hour, per tenant (today: global `llmlimit` token bucket; ❌ no per-tenant, no $/incident hard cap)

## EPIC 10 — Notifier channels (expansion)
- ❌ MS Teams
- ❌ Mattermost
- ❌ OpsGenie
- ❌ Webhook (generic, signed)
- ❌ Notifier health check (test alert button / endpoint)
- ✅ Existing notifiers: Slack, Discord, Telegram, PagerDuty, Email/SMTP

## EPIC 11 — Multi-tenant vendor ops
- 🟡 Per-tenant config (today: per-cluster token mapping, routing rules can match `ClusterID`; ❌ no full per-tenant config object)
- ❌ Tenant onboarding CLI / Helm template
- ❌ Tenant offboarding (data purge endpoint)
- ❌ Tenant usage report (for billing)
- ❌ Tenant-level audit log export

## EPIC 12 — DX / contributor
- ❌ `make dev` simple local setup (kind/k3d + fake AlertManager)
- ❌ Demo alert generator for local test
- 🟡 Integration test suite (today: unit + httptest mocks; ❌ no real Loki/Prom container tests)
- ✅ CLAUDE.md (done)
- ✅ PR templates (done)
- ✅ Branch protection (done)
- ✅ CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md (done)
- ✅ Issue templates (done)

## EPIC 13 — Distribution
- ❌ Homebrew tap (no CLI exists yet → likely skip)
- ❌ Helm chart on artifacthub
- 🟡 Pre-built images (✅ released via CI; ❌ verify multi-arch amd64+arm64)
- ❌ SBOM + cosign signed images
- 🟡 Release notes (✅ exist; ❌ auto-gen from Conventional Commits)

---

## Out of scope (deliberately)

- ~~Custom UI~~ (Grafana panel max)
- ~~Mesh (Tailscale/Headscale)~~ (breaks outbound-only)
- ~~JWKS pull model~~ (depends on client API server reachability)
- ~~Custom metric storage~~ (Prometheus does it better)
- ~~Direct cluster control from brain~~ (trust model)
- ~~Signed protobuf~~ (was in original plan but never implemented; mTLS supersedes the need)

---

## Tech debt / risk register (surfaced by mapping)

- **Proto duplication** — `proto/alert.proto` is copy-pasted between repos. Add a contract sync check to CI (already partially: `make proto-check`) and consider monorepo or git submodule for `proto/`.
- **Global Redis prefix** — `muthur:` keyspace shared across tenants. Multi-tenant work (EPIC 2 / 11) must add tenant prefix.
- **Global cost budget** — one rogue collector can drain LLM budget for all others. Per-tenant bucket needed.
- **No incident-level audit** — redaction stats go into the payload but brain never surfaces them. EPIC 7 audit report fixes this.
- **Tail loss under storms** — correlation max group size 25; alerts beyond that are silently dropped in the same window. Add metric `muthur_correlation_dropped_total` (verify if exists) + document.
- **Feedback IDs are predictable** — SHA256 of cluster+alert+namespace+pod first 12 hex chars. Enumeration possible if attacker knows pod/namespace names. Consider HMAC with a brain-side secret.

---

## Recommended order (depth, not breadth)

1. ✅ EPIC 0 (mapping done)
2. EPIC 2 (mTLS) — biggest value, sales argument, full greenfield
3. EPIC 9 finalization — per-tenant cost backstop + auto-tier on low confidence (small effort, high impact, most of it already exists)
4. EPIC 7 — local LLM polish + air-gapped mode + brain-side audit report
5. EPIC 1 (gRPC stream) — only if EPIC 3 is the next planned thing
6. EPIC 3 (agentic pull) — depends on 1 + 2
7. EPIC 4A (abstraction) → 4B/C/D per demand
8. EPIC 8 (observability polish — Grafana dashboard JSON, per-tenant metric labels) — can be done in slack time alongside others
9. EPIC 11 (multi-tenant ops) — only with real clients
10. EPIC 10 / 12 / 13 — per demand
