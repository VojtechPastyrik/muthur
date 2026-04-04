package pipeline

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur-central/internal/dedup"
	"github.com/VojtechPastyrik/muthur-central/internal/evaluator"
	"github.com/VojtechPastyrik/muthur-central/internal/notify"
	"github.com/VojtechPastyrik/muthur-central/internal/routing"
	"github.com/VojtechPastyrik/muthur-central/internal/silence"
	pb "github.com/VojtechPastyrik/muthur-central/proto"
)

type Pipeline struct {
	dedup     *dedup.Deduplicator
	evaluator *evaluator.Evaluator
	router    *routing.Router
	notifiers map[string]notify.Notifier
	silence   *silence.Client
	grafanaURL string
	logger    *zap.Logger
}

func New(
	dedup *dedup.Deduplicator,
	eval *evaluator.Evaluator,
	router *routing.Router,
	notifiers map[string]notify.Notifier,
	silence *silence.Client,
	grafanaURL string,
	logger *zap.Logger,
) *Pipeline {
	return &Pipeline{
		dedup:      dedup,
		evaluator:  eval,
		router:     router,
		notifiers:  notifiers,
		silence:    silence,
		grafanaURL: grafanaURL,
		logger:     logger,
	}
}

func (p *Pipeline) Process(payload *pb.AlertPayload) {
	if p.dedup.IsDuplicate(payload) {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	analysis, err := p.evaluator.Evaluate(ctx, payload)
	if err != nil {
		p.logger.Error("evaluation failed",
			zap.String("alert", payload.AlertName),
			zap.Error(err),
		)
		// continue with nil analysis — still send notifications
	}

	if analysis != nil && analysis.Silence {
		if err := p.silence.CreateSilence(ctx, payload, analysis.SilenceReason); err != nil {
			p.logger.Error("failed to create silence",
				zap.String("alert", payload.AlertName),
				zap.Error(err),
			)
		}
	}

	targets := p.router.Route(payload)
	if len(targets) == 0 {
		return
	}

	msg := notify.FormatMessage(payload, analysis, p.grafanaURL)

	for _, name := range targets {
		notifier, ok := p.notifiers[name]
		if !ok {
			p.logger.Warn("notifier not registered", zap.String("notifier", name))
			continue
		}

		if err := notifier.Send(ctx, msg); err != nil {
			p.logger.Error("notification failed",
				zap.String("notifier", name),
				zap.String("alert", payload.AlertName),
				zap.Error(err),
			)
		} else {
			p.logger.Info("notification sent",
				zap.String("notifier", name),
				zap.String("alert", payload.AlertName),
			)
		}
	}
}
