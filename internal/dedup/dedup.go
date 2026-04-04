package dedup

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur-central/proto"
)

type Deduplicator struct {
	window time.Duration
	store  sync.Map
	logger *zap.Logger
}

type entry struct {
	expiresAt time.Time
}

func New(windowMinutes int, logger *zap.Logger) *Deduplicator {
	d := &Deduplicator{
		window: time.Duration(windowMinutes) * time.Minute,
		logger: logger,
	}
	go d.cleanup()
	return d
}

func (d *Deduplicator) IsDuplicate(payload *pb.AlertPayload) bool {
	key := d.key(payload)

	if val, ok := d.store.Load(key); ok {
		e := val.(*entry)
		if time.Now().Before(e.expiresAt) {
			d.logger.Info("duplicate alert skipped",
				zap.String("cluster_id", payload.ClusterId),
				zap.String("alert_name", payload.AlertName),
				zap.String("namespace", payload.Namespace),
			)
			return true
		}
	}

	d.store.Store(key, &entry{expiresAt: time.Now().Add(d.window)})
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

func (d *Deduplicator) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		d.store.Range(func(key, value any) bool {
			e := value.(*entry)
			if now.After(e.expiresAt) {
				d.store.Delete(key)
			}
			return true
		})
	}
}
