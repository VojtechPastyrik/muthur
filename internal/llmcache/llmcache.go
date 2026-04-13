package llmcache

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

type Cache struct {
	enabled bool
	ttl     time.Duration
	store   sync.Map
	logger  *zap.Logger
}

type entry struct {
	analysis  *evaluator.Analysis
	expiresAt time.Time
}

func New(enabled bool, ttlMinutes int, logger *zap.Logger) *Cache {
	c := &Cache{
		enabled: enabled,
		ttl:     time.Duration(ttlMinutes) * time.Minute,
		logger:  logger,
	}
	if enabled {
		go c.cleanup()
	}
	return c
}

func (c *Cache) Get(payload *pb.AlertPayload) (*evaluator.Analysis, bool) {
	if !c.enabled {
		return nil, false
	}
	key := c.key(payload)
	val, ok := c.store.Load(key)
	if !ok {
		return nil, false
	}
	e := val.(*entry)
	if time.Now().After(e.expiresAt) {
		c.store.Delete(key)
		return nil, false
	}
	c.logger.Info("llm cache hit",
		zap.String("cluster_id", payload.ClusterId),
		zap.String("alert_name", payload.AlertName),
		zap.String("namespace", payload.Namespace),
	)
	return e.analysis, true
}

func (c *Cache) Set(payload *pb.AlertPayload, analysis *evaluator.Analysis) {
	if !c.enabled || analysis == nil {
		return
	}
	c.store.Store(c.key(payload), &entry{
		analysis:  analysis,
		expiresAt: time.Now().Add(c.ttl),
	})
}

func (c *Cache) key(payload *pb.AlertPayload) string {
	raw := fmt.Sprintf("%s|%s|%s|%s",
		payload.ClusterId,
		payload.AlertName,
		payload.Namespace,
		payload.PodName,
	)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h)
}

func (c *Cache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		c.store.Range(func(key, value any) bool {
			e := value.(*entry)
			if now.After(e.expiresAt) {
				c.store.Delete(key)
			}
			return true
		})
	}
}
