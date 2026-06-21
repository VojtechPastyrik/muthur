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

	// LLMCalls counts Claude API calls by result: ok, error.
	LLMCalls = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_calls_total",
		Help: "Claude API evaluations by result.",
	}, []string{"result"})

	// LLMCallDuration tracks end-to-end Claude evaluation latency.
	LLMCallDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "muthur_llm_call_duration_seconds",
		Help:    "Claude evaluation latency including retries.",
		Buckets: []float64{0.5, 1, 2, 5, 10, 20, 30, 60},
	})

	// LLMTokens counts Claude token usage by direction: input, output.
	LLMTokens = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "muthur_llm_tokens_total",
		Help: "Claude token usage by direction.",
	}, []string{"direction"})

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
