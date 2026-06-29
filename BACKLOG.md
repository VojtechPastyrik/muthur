# MUTHUR backlog

Strategic feature backlog. Short bullets, what — not how.

Positioning anchor: **AI layer over existing Prometheus/AlertManager. Not a replacement.**
North star: thin, privacy-first AI brain for vendors managing client clusters.

**Status legend:** ✅ done · 🟡 partial / exists but limited · ❌ not started · 🚫 dropped/deferred

---

## Findings from EPIC 0 mapping (2026-06-28, partial rewrite 2026-06-29)

The original mapping is preserved below for history; the post-v0.8.4
state is summarised here so a new reader doesn't infer a stale picture.

**Shipped since the original mapping (v0.7-v0.8.4):**
- Wire format moved from REST to gRPC (`monitoring.v1.Brain`).
- Bearer-token auth replaced with mTLS + vendor CA, hot-reloaded
  revocation, replay protection via timestamp + nonce.
- Per-tenant cost backstop, per-tenant metric labels, LLM audit log,
  auto-tier on low confidence, structural anti-prompt-injection
  (system/user role split), redaction extended beyond log lines.

**Still open (highest signal):**
- Per-tenant Redis prefix (multi-tenant safety).
- Proto duplication (mechanical drift risk).
- `air_gapped` mode flag.
- Grafana dashboard JSON checked into the repo.
- ARCHITECTURE.md promotion.

---

Original findings (history, 2026-06-28):

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

## EPIC 1 — Transport: collector → brain gRPC — ✅ shipped v0.8.0
- ✅ Replace POST `/ingest` (and `/bootstrap-cert`, `/sign-csr`) with the
  `monitoring.v1.Brain` gRPC service. Collector dials brain (still
  unary, not streaming — see EPIC 3 for the streaming case)
- 🚫 Long-poll fallback — dropped; gRPC over TLS clears the same
  middleboxes that REST did
- 🚫 Backpressure + auto-reconnect on streams — not needed until
  streaming is added (EPIC 3)
- ✅ No new inbound port on collector (already outbound-only)
- 🟡 Unify proto into a single source of truth — currently duplicated
  in `muthur/proto/` and `muthur-collector/proto/`; CI does not yet
  cross-check
- ✅ `make proto` + tests for the gRPC surface

## EPIC 2 — Auth (mTLS + CA + per-tenant) — ✅ shipped v0.7-v0.8.3
- ✅ Replaced `X-Collector-Token` with mTLS + vendor CA (v0.7.0)
- ✅ Root CA offline, intermediate file-mounted on brain; chart
  auto-provisions root + intermediate via cert-manager when
  `ca.enabled: true`
- ✅ Brain trusts a single root (vendor), verifies offline
- ✅ Identity from cert (SPIFFE URI SAN or CN), never from payload
- ✅ cert-manager in client cluster: collector init container generates
  the key locally and CSRs out
- ✅ CSR signing via vendor intermediate (root never leaves vendor)
- ✅ Auto rotation (`certDuration` per tenant; renewCron on collector)
- ✅ Runtime revocation: `revoked: true` flag-flip propagates within
  ~5s via the tenants config hot-reload (v0.8.2-v0.8.3)
- ✅ Per-tenant rate limit + concurrency (v0.8.4 — `llmlimit.Pool`
  buckets per `cluster_id`)
- ✅ Authz: `identity.cluster_id == payload.cluster_id` enforced at
  ingest, else `PermissionDenied`
- ✅ Replay protection: `x-muthur-timestamp` + single-use `x-muthur-nonce`
  via `auth.ReplayGuard` (v0.8.0)
- ❌ Per-tenant Redis prefix (today: shared `muthur:` prefix → cross-
  tenant data lives in same namespace; tech-debt entry below)
- 🚫 Migration: dual-accept (token+mTLS) — dropped; deployed as a hard
  cut at v0.7.0

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
- ✅ **Local embedder** (`internal/embed/embed.go` — in-process; no
  cloud embedding calls)
- 🟡 **Local LLM** first-class (provider abstraction supports
  OpenAI-compatible → Ollama/vLLM/LM Studio/Groq/Together/OpenRouter
  work today; still missing: prompt tuning for smaller models,
  validated examples in docs, recommended models per task)
- ❌ **"Air-gapped mode"** flag — no egress except brain (refuse to
  start with cloud LLM provider config when set)
- 🟡 **Audit / proof report** — what actually left the cluster
  - ✅ Collector tracks redaction stats (`TotalLogLines`,
    `RedactedLogLines`, `TotalReplacements` + per-category counts when
    `REDACT_LOG_STATS=true`)
  - ✅ Brain LLM audit log (v0.8.2 — `LLM_AUDIT_MODE=off|hash|full`;
    identity + prompt/output hashes + optional bodies)
  - ❌ Per-tenant exportable audit log endpoint (the data is in the
    structured log; surfacing a per-tenant JSONL export is still TODO)
- ✅ **Configurable PII obfuscation across every leaving field**
  (v0.8.1 — annotations, label names + values, metric descriptions
  share the log redactor's pattern set; v0.8.2 adds
  `REDACT_MAX_STRING_BYTES` knob with a fail-closed marker)

## EPIC 8 — MUTHUR observability — 🟡
- ✅ Prometheus metrics with per-tenant `cluster_id` label (v0.8.4 —
  `LLMCalls`, `LLMTokens`, `LLMCallDuration`, `LLMValidationFailures`,
  `LLMRetries`, `LLMDegraded`, `LLMThrottled` all carry `cluster_id`)
- ❌ Ship Grafana dashboard (JSON in repo, no custom UI)
- ❌ OpenTelemetry traces brain → LLM → notifier
- 🟡 Cost report ($) per tenant — token counters carry `cluster_id`
  so a Grafana panel can multiply by provider $/token; no $ math
  shipped in MUTHUR itself
- ✅ "Incident recurrence" (exists via deterministic alertkey +
  `IncidentHistory` store)

## EPIC 9 — Trust calibration for LLM output — 🟡
- ✅ **Confidence score per analysis** (`Analysis.Confidence`:
  high/medium/low; surfaced in every notifier's `ConfidenceLine`)
- 🟡 **"Why this severity" rationale** (`Analysis.Grounding`:
  stated/inferred — boolean-ish signal, not yet a free-text rationale)
- ✅ **Feedback loop: human label "useful/wrong"** (`/feedback?id=&verdict=`
  endpoint + Redis-backed verdict store, 30d TTL)
- ✅ **Prompt tuning via few-shot replay** (recent verdicts replayed as
  `Example`s in next prompt)
- ✅ **Auto-tier on low confidence** (v0.8.4 — `confidence: low`
  refuses auto-silence and emits
  `muthur_silences_total{result="low_confidence"}` so a chronically
  uncertain model is visible)
- ✅ **Per-tenant cost backstop** (v0.8.4 — `llmlimit.Pool` gives every
  `cluster_id` its own rate + concurrency bucket so one noisy tenant
  cannot drain the budget for others). ❌ Still no $/incident hard cap
  (cost-per-call modelling left to the operator's Grafana panel using
  the per-tenant `LLMTokens` counter)

## EPIC 10 — Notifier channels (expansion)
- ❌ MS Teams
- ❌ Mattermost
- ❌ OpsGenie
- ✅ Generic webhook (`internal/notify/webhook.go` — JSON POST with the
  full structured payload; HMAC signing still ❌)
- ❌ Notifier health check (test alert button / endpoint)
- ✅ Existing notifiers: Slack, Discord, Telegram, PagerDuty, Email/SMTP,
  Webhook

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
