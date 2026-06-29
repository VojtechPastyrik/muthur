// Package llmlimit is the final cost backstop in front of the Claude API.
//
// Correlation, dedup, and caching cut LLM calls on the happy path, but none of
// them bound a pathological storm of distinct, uncacheable alerts (a genuine
// cluster meltdown, or an attacker holding a valid collector token). This
// limiter caps both the sustained call rate (a token bucket) and the number of
// concurrent in-flight calls (a semaphore). When either ceiling is hit, Acquire
// returns false and the caller is expected to fall back to raw alert delivery —
// the system degrades to a dumb forwarder under load instead of running up an
// unbounded API bill or spawning unbounded goroutines.
package llmlimit

import (
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/metrics"
)

// Limiter bounds LLM call rate and concurrency. The zero value is not usable;
// construct with New. A nil *Limiter is safe and unlimited (Acquire always
// returns true), which keeps tests and the disabled path simple.
type Limiter struct {
	mu           sync.Mutex
	tokens       float64
	maxTokens    float64
	refillPerSec float64
	last         time.Time

	concurrency chan struct{}
	logger      *zap.Logger
}

// New builds a Limiter. callsPerMinute is the sustained ceiling; burst is the
// maximum number of calls allowed in an instantaneous spike (the token-bucket
// depth); maxConcurrent caps simultaneous in-flight calls. A non-positive
// callsPerMinute or maxConcurrent returns nil (unlimited).
func New(callsPerMinute, burst, maxConcurrent int, logger *zap.Logger) *Limiter {
	if callsPerMinute <= 0 || maxConcurrent <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = callsPerMinute
	}
	return &Limiter{
		tokens:       float64(burst),
		maxTokens:    float64(burst),
		refillPerSec: float64(callsPerMinute) / 60.0,
		last:         time.Now(),
		concurrency:  make(chan struct{}, maxConcurrent),
		logger:       logger,
	}
}

// Acquire reserves one rate token and one concurrency slot. It never blocks: if
// either ceiling is hit it records the reason against the calling tenant and
// returns false. On true, the caller MUST call Release exactly once when the
// LLM call finishes.
//
// clusterID labels the throttle metric so an operator can tell which tenant
// is consuming the global budget. The limiter itself is still global — see
// the per-tenant bucket helper for cost-isolation.
func (l *Limiter) Acquire(clusterID string) bool {
	if l == nil {
		return true
	}

	// Concurrency slot first — cheapest to check and release.
	select {
	case l.concurrency <- struct{}{}:
	default:
		metrics.LLMThrottled.WithLabelValues("concurrency", clusterID).Inc()
		return false
	}

	l.mu.Lock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.refillPerSec
	if l.tokens > l.maxTokens {
		l.tokens = l.maxTokens
	}
	l.last = now
	if l.tokens < 1 {
		l.mu.Unlock()
		<-l.concurrency // give the slot back
		metrics.LLMThrottled.WithLabelValues("rate", clusterID).Inc()
		return false
	}
	l.tokens--
	l.mu.Unlock()
	return true
}

// Release returns a concurrency slot taken by a successful Acquire. clusterID
// is accepted for symmetry with Acquire; on the per-tenant Pool below it picks
// the right bucket to return the slot to.
func (l *Limiter) Release(_ string) {
	if l == nil {
		return
	}
	select {
	case <-l.concurrency:
	default:
	}
}

// Pool gives each tenant its own Limiter so a noisy collector cannot drain
// the global LLM budget for every other tenant. Buckets are lazy-allocated on
// first Acquire and persist for the lifetime of the process — the tenant set
// is small (handful per vendor), so map growth is bounded by the configured
// tenants list, not by attacker-controlled cluster_ids (RevocationInterceptor
// rejects unknown tenants before they reach the pipeline).
//
// A nil *Pool is safe and unlimited, mirroring *Limiter.
type Pool struct {
	mu             sync.Mutex
	buckets        map[string]*Limiter
	callsPerMinute int
	burst          int
	maxConcurrent  int
	logger         *zap.Logger
}

// NewPool builds a Pool. Bucket parameters are the per-tenant ceilings: each
// cluster_id gets its own bucket sized this way. Non-positive callsPerMinute
// or maxConcurrent returns nil (unlimited), matching New's contract.
func NewPool(callsPerMinute, burst, maxConcurrent int, logger *zap.Logger) *Pool {
	if callsPerMinute <= 0 || maxConcurrent <= 0 {
		return nil
	}
	return &Pool{
		buckets:        make(map[string]*Limiter),
		callsPerMinute: callsPerMinute,
		burst:          burst,
		maxConcurrent:  maxConcurrent,
		logger:         logger,
	}
}

// Acquire selects the bucket for clusterID (creating it on first use) and
// reserves a rate token + concurrency slot from that bucket. Returns false
// without affecting any other tenant's bucket when this tenant is at its
// ceiling.
func (p *Pool) Acquire(clusterID string) bool {
	if p == nil {
		return true
	}
	bucket := p.bucket(clusterID)
	return bucket.Acquire(clusterID)
}

// Release returns the slot to the calling tenant's bucket.
func (p *Pool) Release(clusterID string) {
	if p == nil {
		return
	}
	bucket := p.bucket(clusterID)
	bucket.Release(clusterID)
}

func (p *Pool) bucket(clusterID string) *Limiter {
	p.mu.Lock()
	defer p.mu.Unlock()
	if b, ok := p.buckets[clusterID]; ok {
		return b
	}
	b := New(p.callsPerMinute, p.burst, p.maxConcurrent, p.logger)
	p.buckets[clusterID] = b
	return b
}
