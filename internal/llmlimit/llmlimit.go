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
// either ceiling is hit it records the reason, releases anything it took, and
// returns false. On true, the caller MUST call Release exactly once when the LLM
// call finishes.
func (l *Limiter) Acquire() bool {
	if l == nil {
		return true
	}

	// Concurrency slot first — cheapest to check and release.
	select {
	case l.concurrency <- struct{}{}:
	default:
		metrics.LLMThrottled.WithLabelValues("concurrency").Inc()
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
		metrics.LLMThrottled.WithLabelValues("rate").Inc()
		return false
	}
	l.tokens--
	l.mu.Unlock()
	return true
}

// Release returns a concurrency slot taken by a successful Acquire.
func (l *Limiter) Release() {
	if l == nil {
		return
	}
	select {
	case <-l.concurrency:
	default:
	}
}
