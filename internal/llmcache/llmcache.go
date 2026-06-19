// Package llmcache caches Claude analyses so identical or near-identical alerts
// don't re-incur an API call. It supports two layers:
//
//   - Exact cache: keyed on cluster|alert|namespace|pod (same key as dedup).
//   - Semantic cache: an alert signature is embedded into a vector and matched
//     against recently cached analyses by cosine similarity, so "same root
//     cause, different pod" is reused even though the exact key differs.
//
// Both layers live in the shared Store, so the cache is warm across replicas and
// survives restarts when backed by Redis/Dragonfly.
package llmcache

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/embed"
	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	"github.com/VojtechPastyrik/muthur/internal/metrics"
	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

type Cache struct {
	enabled   bool
	ttl       time.Duration
	store     store.Store
	embedder  embed.Embedder
	semantic  bool
	threshold float64
	logger    *zap.Logger
}

// vecEntry is the stored representation of a semantic-cache vector and the
// analysis it maps to.
type vecEntry struct {
	Vec      []float32           `json:"vec"`
	Analysis *evaluator.Analysis `json:"analysis"`
}

// New builds a cache. When emb is non-nil and semantic is true, the semantic
// layer is active; threshold is the minimum cosine similarity for a semantic
// hit (0.95 is a sensible default — high enough to avoid false reuse).
func New(enabled bool, ttlMinutes int, st store.Store, emb embed.Embedder, semantic bool, threshold float64, logger *zap.Logger) *Cache {
	return &Cache{
		enabled:   enabled,
		ttl:       time.Duration(ttlMinutes) * time.Minute,
		store:     st,
		embedder:  emb,
		semantic:  semantic && emb != nil,
		threshold: threshold,
		logger:    logger,
	}
}

func (c *Cache) Get(ctx context.Context, payload *pb.AlertPayload) (*evaluator.Analysis, bool) {
	if !c.enabled {
		return nil, false
	}

	// Exact layer.
	if data, ok, err := c.store.Get(ctx, "cache:"+c.key(payload)); err != nil {
		c.logger.Warn("cache get error", zap.Error(err))
	} else if ok {
		var a evaluator.Analysis
		if err := json.Unmarshal(data, &a); err == nil {
			metrics.CacheLookups.WithLabelValues("exact_hit").Inc()
			c.logger.Info("llm cache hit (exact)",
				zap.String("cluster_id", payload.ClusterId),
				zap.String("alert_name", payload.AlertName),
			)
			return &a, true
		}
	}

	// Semantic layer.
	if c.semantic {
		if a, sim, ok := c.semanticLookup(ctx, payload); ok {
			metrics.CacheLookups.WithLabelValues("semantic_hit").Inc()
			c.logger.Info("llm cache hit (semantic)",
				zap.String("cluster_id", payload.ClusterId),
				zap.String("alert_name", payload.AlertName),
				zap.Float64("similarity", sim),
			)
			return a, true
		}
	}

	metrics.CacheLookups.WithLabelValues("miss").Inc()
	return nil, false
}

func (c *Cache) Set(ctx context.Context, payload *pb.AlertPayload, analysis *evaluator.Analysis) {
	if !c.enabled || analysis == nil {
		return
	}
	data, err := json.Marshal(analysis)
	if err != nil {
		return
	}
	if err := c.store.Set(ctx, "cache:"+c.key(payload), data, c.ttl); err != nil {
		c.logger.Warn("cache set error", zap.Error(err))
	}

	if c.semantic {
		entry := vecEntry{Vec: c.embedder.Embed(evaluator.Signature(payload)), Analysis: analysis}
		if b, err := json.Marshal(entry); err == nil {
			if err := c.store.Set(ctx, "vec:"+c.key(payload), b, c.ttl); err != nil {
				c.logger.Warn("semantic cache set error", zap.Error(err))
			}
		}
	}
}

// semanticLookup scans recent vectors for the best cosine match above the
// threshold. The scan is linear; alert volume per TTL window is small enough
// that this is cheap, and it avoids pulling in a vector database.
func (c *Cache) semanticLookup(ctx context.Context, payload *pb.AlertPayload) (*evaluator.Analysis, float64, bool) {
	vals, err := c.store.ListByPrefix(ctx, "vec:")
	if err != nil {
		c.logger.Warn("semantic cache scan error", zap.Error(err))
		return nil, 0, false
	}
	query := c.embedder.Embed(evaluator.Signature(payload))
	var best *evaluator.Analysis
	var bestSim float64
	for _, raw := range vals {
		var e vecEntry
		if err := json.Unmarshal(raw, &e); err != nil || e.Analysis == nil {
			continue
		}
		sim := embed.Cosine(query, e.Vec)
		if sim > bestSim {
			bestSim = sim
			best = e.Analysis
		}
	}
	if best != nil && bestSim >= c.threshold {
		return best, bestSim, true
	}
	return nil, 0, false
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
