package pipeline

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/dedup"
	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	"github.com/VojtechPastyrik/muthur/internal/feedback"
	"github.com/VojtechPastyrik/muthur/internal/history"
	"github.com/VojtechPastyrik/muthur/internal/incident"
	"github.com/VojtechPastyrik/muthur/internal/llmcache"
	"github.com/VojtechPastyrik/muthur/internal/llmlimit"
	"github.com/VojtechPastyrik/muthur/internal/metrics"
	"github.com/VojtechPastyrik/muthur/internal/notify"
	"github.com/VojtechPastyrik/muthur/internal/routing"
	"github.com/VojtechPastyrik/muthur/internal/silence"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// CorrelationConfig controls alert correlation. When Enabled is false the
// pipeline processes each alert independently (the original behaviour).
type CorrelationConfig struct {
	Enabled       bool
	WindowSeconds int
	MaxGroup      int
}

type Pipeline struct {
	dedup      *dedup.Deduplicator
	evaluator  evaluator.Analyzer
	cache      *llmcache.Cache
	limiter    *llmlimit.Pool
	router     *routing.Router
	notifiers  map[string]notify.Notifier
	silence    *silence.Client
	feedback   *feedback.Manager
	history    *history.Store
	evidence   notify.EvidenceConfig
	correlator *incident.Correlator
	logger     *zap.Logger
}

func New(
	dd *dedup.Deduplicator,
	eval evaluator.Analyzer,
	cache *llmcache.Cache,
	limiter *llmlimit.Pool,
	router *routing.Router,
	notifiers map[string]notify.Notifier,
	silence *silence.Client,
	fb *feedback.Manager,
	hist *history.Store,
	evidence notify.EvidenceConfig,
	corr CorrelationConfig,
	logger *zap.Logger,
) *Pipeline {
	p := &Pipeline{
		dedup:     dd,
		evaluator: eval,
		cache:     cache,
		limiter:   limiter,
		router:    router,
		notifiers: notifiers,
		silence:   silence,
		feedback:  fb,
		history:   hist,
		evidence:  evidence,
		logger:    logger,
	}
	p.correlator = incident.New(corr.Enabled, corr.WindowSeconds, corr.MaxGroup, p.processIncident, logger)
	return p
}

// Drain flushes any buffered correlation buckets synchronously. Call during
// graceful shutdown before exiting.
func (p *Pipeline) Drain() {
	p.correlator.Drain()
}

// Process is the entry point for a single ingested alert.
func (p *Pipeline) Process(payload *pb.AlertPayload) {
	metrics.AlertsReceived.WithLabelValues(payload.ClusterId, statusLabel(payload)).Inc()

	// Resolved alerts bypass Claude and correlation: they carry no analysis
	// and should be delivered promptly to close the loop on the receiver
	// side. They still dedupe — AlertManager re-sends the whole group on
	// every group state change, so the same resolved alert arrives multiple
	// times.
	if payload.Status == "resolved" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		dup := p.dedup.IsDuplicateResolved(ctx, payload)
		cancel()
		if dup {
			return
		}
		p.processResolved(payload)
		return
	}

	// Dedup before correlation so duplicate firings never inflate an incident.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	dup := p.dedup.IsDuplicate(ctx, payload)
	cancel()
	if dup {
		return
	}

	if p.correlator.Enabled() {
		p.correlator.Add(payload)
		return
	}
	p.processSingle(payload)
}

func (p *Pipeline) processSingle(payload *pb.AlertPayload) {
	metrics.PipelineInFlight.Inc()
	defer metrics.PipelineInFlight.Dec()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	analysis := p.evaluate(ctx, payload)
	p.maybeSilence(ctx, payload, analysis)
	p.history.Record(ctx, payload, analysis, []*pb.AlertPayload{payload})

	msg := notify.FormatMessage(payload, analysis)
	notify.AttachEvidence(msg, payload, p.evidence)
	p.attachFeedback(ctx, payload, analysis, msg)
	p.deliver(ctx, payload, msg)
}

// processIncident is the correlator flush callback: one LLM evaluation and one
// notification for the whole group.
func (p *Pipeline) processIncident(alerts []*pb.AlertPayload) {
	metrics.PipelineInFlight.Inc()
	defer metrics.PipelineInFlight.Dec()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	rep := incident.Representative(alerts)
	if rep == nil {
		return
	}

	// A single-alert "incident" is just a normal alert — render it as one.
	if len(alerts) == 1 {
		analysis := p.evaluate(ctx, rep)
		p.maybeSilence(ctx, rep, analysis)
		p.history.Record(ctx, rep, analysis, alerts)
		msg := notify.FormatMessage(rep, analysis)
		notify.AttachEvidence(msg, rep, p.evidence)
		p.attachFeedback(ctx, rep, analysis, msg)
		p.deliver(ctx, rep, msg)
		metrics.Incidents.WithLabelValues(metrics.IncidentSizeBucket(1)).Inc()
		return
	}

	analysis := p.evaluateIncident(ctx, rep, alerts)
	p.maybeSilence(ctx, rep, analysis)
	p.history.Record(ctx, rep, analysis, alerts)

	msg := notify.FormatIncidentMessage(rep, alerts, analysis)
	notify.AttachEvidence(msg, rep, p.evidence)
	p.attachFeedback(ctx, rep, analysis, msg)
	p.deliver(ctx, rep, msg)

	metrics.Incidents.WithLabelValues(metrics.IncidentSizeBucket(len(alerts))).Inc()
	p.logger.Info("incident notified",
		zap.String("cluster_id", rep.ClusterId),
		zap.Int("alerts", len(alerts)),
	)
}

func (p *Pipeline) processResolved(payload *pb.AlertPayload) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	msg := notify.FormatMessage(payload, nil)
	p.deliver(ctx, payload, msg)
}

// evaluate returns the analysis for a single alert: cache first, then Claude
// (with operator feedback as few-shot), caching the fresh result.
func (p *Pipeline) evaluate(ctx context.Context, payload *pb.AlertPayload) *evaluator.Analysis {
	if cached, ok := p.cache.Get(ctx, payload); ok {
		return cached
	}
	// Cost backstop: under a storm of uncacheable alerts, skip the LLM and
	// deliver the raw alert rather than run up an unbounded bill.
	if !p.limiter.Acquire(payload.ClusterId) {
		p.logger.Warn("LLM cost backstop hit, delivering raw alert",
			zap.String("alert", payload.AlertName),
			zap.String("cluster_id", payload.ClusterId),
		)
		return nil
	}
	defer p.limiter.Release(payload.ClusterId)
	examples := p.feedback.Examples(ctx, payload)
	analysis, err := p.evaluator.Evaluate(ctx, payload, examples)
	if err != nil {
		p.logger.Error("evaluation failed",
			zap.String("alert", payload.AlertName),
			zap.Error(err),
		)
		return nil
	}
	p.cache.Set(ctx, payload, analysis)
	return analysis
}

// evaluateIncident asks Claude for one unified analysis across the group.
// Incidents are not cached — each correlated group is unique.
func (p *Pipeline) evaluateIncident(ctx context.Context, rep *pb.AlertPayload, alerts []*pb.AlertPayload) *evaluator.Analysis {
	if !p.limiter.Acquire(rep.ClusterId) {
		p.logger.Warn("LLM cost backstop hit, delivering raw incident",
			zap.String("cluster_id", rep.ClusterId),
			zap.Int("alerts", len(alerts)),
		)
		return nil
	}
	defer p.limiter.Release(rep.ClusterId)
	examples := p.feedback.Examples(ctx, rep)
	analysis, err := p.evaluator.EvaluateIncident(ctx, alerts, examples)
	if err != nil {
		p.logger.Error("incident evaluation failed",
			zap.String("cluster_id", rep.ClusterId),
			zap.Int("alerts", len(alerts)),
			zap.Error(err),
		)
		return nil
	}
	return analysis
}

func (p *Pipeline) maybeSilence(ctx context.Context, payload *pb.AlertPayload, analysis *evaluator.Analysis) {
	if analysis == nil || !analysis.Silence {
		return
	}
	// Auto-tier on low confidence: the model itself flagged that its verdict
	// is a guess, not a data-grounded conclusion. Refusing the silence keeps
	// the page on call so a human can verify; the notification still carries
	// the LLM analysis with `confidence: low` so on-call sees the model's
	// reasoning as advisory rather than authoritative. The
	// `low_confidence` result joins the existing `blocked` outcomes
	// (critical severity, allowlist miss) in the silences metric so an
	// operator can spot a model that's chronically uncertain.
	if analysis.Confidence == "low" {
		metrics.Silences.WithLabelValues("low_confidence").Inc()
		p.logger.Info("auto-silence refused: analysis confidence is low",
			zap.String("alert", payload.AlertName),
			zap.String("cluster_id", payload.ClusterId),
		)
		return
	}
	if err := p.silence.CreateSilence(ctx, payload, analysis.SilenceReason); err != nil {
		p.logger.Error("failed to create silence",
			zap.String("alert", payload.AlertName),
			zap.Error(err),
		)
	}
}

func (p *Pipeline) attachFeedback(ctx context.Context, payload *pb.AlertPayload, analysis *evaluator.Analysis, msg *notify.Message) {
	if analysis == nil {
		return
	}
	up, down := p.feedback.Record(ctx, payload, analysis)
	msg.FeedbackUpURL = up
	msg.FeedbackDownURL = down
}

func (p *Pipeline) deliver(ctx context.Context, routeBy *pb.AlertPayload, msg *notify.Message) {
	targets := p.router.Route(routeBy)
	if len(targets) == 0 {
		return
	}
	for _, name := range targets {
		notifier, ok := p.notifiers[name]
		if !ok {
			p.logger.Warn("notifier not registered", zap.String("notifier", name))
			continue
		}
		if err := notifier.Send(ctx, msg); err != nil {
			metrics.Notifications.WithLabelValues(name, "error").Inc()
			p.logger.Error("notification failed",
				zap.String("notifier", name),
				zap.String("alert", routeBy.AlertName),
				zap.Error(err),
			)
		} else {
			metrics.Notifications.WithLabelValues(name, "ok").Inc()
			p.logger.Info("notification sent",
				zap.String("notifier", name),
				zap.String("alert", routeBy.AlertName),
			)
		}
	}
}

func statusLabel(payload *pb.AlertPayload) string {
	if payload.Status == "resolved" {
		return "resolved"
	}
	return "firing"
}
