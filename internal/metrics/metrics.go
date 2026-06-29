// Package metrics exposes Prometheus instrumentation for muthur-central so the
// monitoring tool can itself be monitored: alert throughput, dedup/cache
// effectiveness, LLM cost and latency, notification delivery, incident
// correlation, and operator feedback.
//
// All metrics live in the muthur_ namespace and are registered against the
// default registry, served at /metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AlertsReceived counts ingested alert payloads by cluster and status.
	AlertsReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_alerts_received_total",
		Help: "Alert payloads accepted at /ingest.",
	}, []string{"cluster", "status"})

	// AlertsDeduped counts alerts dropped by the dedup window.
	AlertsDeduped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_alerts_deduped_total",
		Help: "Alerts skipped because an identical alert is within the dedup window.",
	}, []string{"cluster"})

	// CacheLookups counts LLM-cache lookups by result: exact_hit, semantic_hit, miss.
	CacheLookups = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_cache_lookups_total",
		Help: "LLM analysis cache lookups by result.",
	}, []string{"result"})

	// LLM-related metrics carry a cluster_id label so cost, reliability, and
	// validation behaviour can be attributed to the tenant whose alert
	// triggered the call. Cardinality is bounded by the tenants list, which
	// is small (handful per vendor); high-cardinality concerns from "label
	// every payload" do not apply.
	//
	// LLMCalls counts LLM evaluations by result (ok, error), provider,
	// model, and the originating cluster_id.
	LLMCalls = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_calls_total",
		Help: "LLM evaluations by result, provider, model, and cluster_id.",
	}, []string{"result", "provider", "model", "cluster_id"})

	// LLMCallDuration tracks end-to-end LLM evaluation latency, labelled by
	// the serving provider, model, and originating cluster_id.
	LLMCallDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "muthur_llm_call_duration_seconds",
		Help:    "LLM evaluation latency including retries, by provider, model, and cluster_id.",
		Buckets: []float64{0.5, 1, 2, 5, 10, 20, 30, 60},
	}, []string{"provider", "model", "cluster_id"})

	// LLMTokens counts LLM token usage by direction (input, output),
	// provider, model, and cluster_id. The cluster_id label is what makes
	// per-tenant cost billing possible.
	LLMTokens = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_tokens_total",
		Help: "LLM token usage by direction, provider, model, and cluster_id.",
	}, []string{"direction", "provider", "model", "cluster_id"})

	// LLMValidationFailures counts LLM outputs that failed canonical-schema
	// validation, by provider, model, and cluster_id. A non-zero rate means
	// a model is struggling to honour the structured-output contract — split
	// by cluster_id surfaces whether one tenant's payloads are unusually
	// pathological.
	LLMValidationFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_validation_failures_total",
		Help: "LLM outputs that failed canonical-schema validation, by provider, model, and cluster_id.",
	}, []string{"provider", "model", "cluster_id"})

	// LLMRetries counts corrective retries issued after a validation failure,
	// by provider, model, and cluster_id.
	LLMRetries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_retries_total",
		Help: "Corrective structured-output retries, by provider, model, and cluster_id.",
	}, []string{"provider", "model", "cluster_id"})

	// LLMDegraded counts evaluations that exhausted their corrective retries
	// and degraded to raw delivery, by provider, model, and cluster_id. This
	// is the honest fallback — never a silent markdown/JSON parse.
	LLMDegraded = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_degraded_total",
		Help: "Evaluations degraded to raw delivery after structured-output retries, by provider, model, and cluster_id.",
	}, []string{"provider", "model", "cluster_id"})

	// LLMThrottled counts LLM evaluations skipped by the cost backstop, by
	// reason (rate or concurrency) and cluster_id. A throttled alert is still
	// delivered, just without Claude enrichment.
	LLMThrottled = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_throttled_total",
		Help: "LLM evaluations skipped by the rate/concurrency backstop, by reason and cluster_id.",
	}, []string{"reason", "cluster_id"})

	// Silences counts AlertManager silence outcomes by result: created, blocked
	// (refused by a guard), error.
	Silences = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_silences_total",
		Help: "AlertManager auto-silence outcomes by result.",
	}, []string{"result"})

	// Notifications counts delivery attempts by receiver and result: ok, error.
	Notifications = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_notifications_total",
		Help: "Notification delivery attempts by receiver and result.",
	}, []string{"receiver", "result"})

	// Incidents counts correlated incidents emitted, labelled by the number of
	// alerts grouped (bucketed as "1", "2-5", "6+").
	Incidents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_incidents_total",
		Help: "Correlated incidents emitted, bucketed by grouped-alert count.",
	}, []string{"size"})

	// Feedback counts operator verdicts on analyses by verdict: useful, wrong.
	Feedback = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_feedback_total",
		Help: "Operator feedback verdicts on Claude analyses.",
	}, []string{"verdict"})

	// IncidentsRecorded counts incident records persisted to history.
	IncidentsRecorded = promauto.NewCounter(prometheus.CounterOpts{
		Name: "muthur_incidents_recorded_total",
		Help: "Incident records persisted to history.",
	})

	// PipelineInFlight tracks alerts/incidents currently being processed.
	PipelineInFlight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "muthur_pipeline_in_flight",
		Help: "Alerts or incidents currently being processed by the pipeline.",
	})
)

// IncidentSizeBucket maps a grouped-alert count to a low-cardinality label.
func IncidentSizeBucket(n int) string {
	switch {
	case n <= 1:
		return "1"
	case n <= 5:
		return "2-5"
	default:
		return "6+"
	}
}
