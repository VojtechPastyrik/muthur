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

// IsDuplicateResolved reports whether the resolved notification for this
// firing episode was already delivered. AlertManager re-sends the whole alert
// group on every group state change, so a resolved alert arrives again each
// time a sibling alert fires or resolves; without this check every re-send
// produces a duplicate "alert cleared" notification. The key includes FiredAt
// so a genuinely new firing episode of the same alert still gets its own
// resolved notification. Fails open on store errors, like IsDuplicate.
func (d *Deduplicator) IsDuplicateResolved(ctx context.Context, payload *pb.AlertPayload) bool {
	key := "dedup:resolved:" + d.resolvedKey(payload)
	set, err := d.store.SetNX(ctx, key, []byte("1"), d.window)
	if err != nil {
		d.logger.Warn("resolved dedup store error, treating as not-duplicate",
			zap.String("alert_name", payload.AlertName),
			zap.Error(err),
		)
		return false
	}
	if !set {
		metrics.AlertsDeduped.WithLabelValues(payload.ClusterId).Inc()
		d.logger.Info("duplicate resolved alert skipped",
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

// resolvedKey additionally pins the firing timestamp so each firing episode
// gets exactly one resolved notification.
func (d *Deduplicator) resolvedKey(payload *pb.AlertPayload) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%d",
		payload.ClusterId,
		payload.AlertName,
		payload.Namespace,
		payload.PodName,
		payload.FiredAt,
	)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h)
}
