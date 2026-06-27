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

	// LLMCalls counts LLM evaluations by result (ok, error) and by the backend
	// that served them (provider, model), so cost and reliability can be broken
	// down per provider when more than one is in play.
	LLMCalls = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_calls_total",
		Help: "LLM evaluations by result, provider, and model.",
	}, []string{"result", "provider", "model"})

	// LLMCallDuration tracks end-to-end LLM evaluation latency, labelled by the
	// serving provider and model.
	LLMCallDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "muthur_llm_call_duration_seconds",
		Help:    "LLM evaluation latency including retries, by provider and model.",
		Buckets: []float64{0.5, 1, 2, 5, 10, 20, 30, 60},
	}, []string{"provider", "model"})

	// LLMTokens counts LLM token usage by direction (input, output), provider,
	// and model.
	LLMTokens = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_tokens_total",
		Help: "LLM token usage by direction, provider, and model.",
	}, []string{"direction", "provider", "model"})

	// LLMValidationFailures counts LLM outputs that failed canonical-schema
	// validation, by provider and model. A non-zero rate means a model is
	// struggling to honour the structured-output contract.
	LLMValidationFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_validation_failures_total",
		Help: "LLM outputs that failed canonical-schema validation, by provider and model.",
	}, []string{"provider", "model"})

	// LLMRetries counts corrective retries issued after a validation failure,
	// by provider and model.
	LLMRetries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_retries_total",
		Help: "Corrective structured-output retries, by provider and model.",
	}, []string{"provider", "model"})

	// LLMDegraded counts evaluations that exhausted their corrective retries and
	// degraded to raw delivery, by provider and model. This is the honest
	// fallback — never a silent markdown/JSON parse.
	LLMDegraded = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_degraded_total",
		Help: "Evaluations degraded to raw delivery after structured-output retries, by provider and model.",
	}, []string{"provider", "model"})

	// LLMThrottled counts LLM evaluations skipped by the cost backstop, by
	// reason: rate (calls-per-minute ceiling) or concurrency (in-flight cap).
	// A throttled alert is still delivered, just without Claude enrichment.
	LLMThrottled = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_throttled_total",
		Help: "LLM evaluations skipped by the rate/concurrency backstop, by reason.",
	}, []string{"reason"})

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
