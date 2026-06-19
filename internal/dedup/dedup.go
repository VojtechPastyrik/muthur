package dedup

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/metrics"
	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// Deduplicator drops repeat firings of the same alert within a sliding window.
// State lives in the shared Store, so with a Redis/Dragonfly backend dedup is
// consistent across muthur-central replicas; with the in-memory backend it is
// per-instance.
type Deduplicator struct {
	window time.Duration
	store  store.Store
	logger *zap.Logger
}

func New(windowMinutes int, st store.Store, logger *zap.Logger) *Deduplicator {
	return &Deduplicator{
		window: time.Duration(windowMinutes) * time.Minute,
		store:  st,
		logger: logger,
	}
}

// IsDuplicate reports whether an identical alert is already within the window.
// It uses an atomic set-if-absent so concurrent duplicates resolve correctly.
// On a store error it fails open (returns false) — dropping a real alert is
// worse than processing a duplicate.
func (d *Deduplicator) IsDuplicate(ctx context.Context, payload *pb.AlertPayload) bool {
	key := "dedup:" + d.key(payload)
	set, err := d.store.SetNX(ctx, key, []byte("1"), d.window)
	if err != nil {
		d.logger.Warn("dedup store error, treating as not-duplicate",
			zap.String("alert_name", payload.AlertName),
			zap.Error(err),
		)
		return false
	}
	if !set {
		metrics.AlertsDeduped.WithLabelValues(payload.ClusterId).Inc()
		d.logger.Info("duplicate alert skipped",
			zap.String("cluster_id", payload.ClusterId),
			zap.String("alert_name", payload.AlertName),
			zap.String("namespace", payload.Namespace),
		)
		return true
	}
	return false
}

func (d *Deduplicator) key(payload *pb.AlertPayload) string {
	raw := fmt.Sprintf("%s|%s|%s|%s",
		payload.ClusterId,
		payload.AlertName,
		payload.Namespace,
		payload.PodName,
	)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h)
}
