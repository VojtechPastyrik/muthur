// Package incident groups alerts that fire close together into a single
// incident, so a cascading failure (a node dies, 30 pods alert) becomes one
// LLM evaluation and one notification instead of 30. This is the core
// alert-fatigue reduction: muthur acts as an incident commander, not a fan-out
// relay.
//
// Correlation is a short debounce: the first alert for a group key opens a
// bucket and starts a timer; alerts arriving within the window join the bucket;
// when the timer fires the whole group is flushed to the pipeline as one
// incident. It is opt-in — when disabled the pipeline processes each alert
// independently, preserving the original behaviour.
package incident

import (
	"sync"
	"time"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

// FlushFunc receives a correlated group of alerts (always at least one).
type FlushFunc func(alerts []*pb.AlertPayload)

type Correlator struct {
	enabled  bool
	window   time.Duration
	maxGroup int
	flush    FlushFunc
	logger   *zap.Logger

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	alerts []*pb.AlertPayload
	timer  *time.Timer
}

// New builds a Correlator. windowSeconds is the debounce window; maxGroup caps
// how many alerts a single incident may hold (excess alerts in the same window
// open a fresh bucket on the next tick). flush is invoked, in its own
// goroutine, once per completed group.
func New(enabled bool, windowSeconds, maxGroup int, flush FlushFunc, logger *zap.Logger) *Correlator {
	if maxGroup <= 0 {
		maxGroup = 25
	}
	return &Correlator{
		enabled:  enabled,
		window:   time.Duration(windowSeconds) * time.Second,
		maxGroup: maxGroup,
		flush:    flush,
		logger:   logger,
		buckets:  make(map[string]*bucket),
	}
}

// Enabled reports whether correlation is active.
func (c *Correlator) Enabled() bool { return c.enabled }

// Add buffers an alert into its group. The group is flushed after the debounce
// window elapses with no … well, after the window from the first alert.
func (c *Correlator) Add(payload *pb.AlertPayload) {
	key := groupKey(payload)

	c.mu.Lock()
	b, ok := c.buckets[key]
	if !ok || len(b.alerts) >= c.maxGroup {
		b = &bucket{}
		c.buckets[key] = b
		b.timer = time.AfterFunc(c.window, func() { c.flushKey(key) })
	}
	b.alerts = append(b.alerts, payload)
	n := len(b.alerts)
	c.mu.Unlock()

	c.logger.Debug("alert added to incident bucket",
		zap.String("group", key),
		zap.Int("group_size", n),
	)
}

// Drain flushes every pending bucket immediately and synchronously. Used at
// shutdown so buffered alerts are not lost when the process exits before their
// debounce window elapses.
func (c *Correlator) Drain() {
	c.mu.Lock()
	keys := make([]string, 0, len(c.buckets))
	for k, b := range c.buckets {
		if b.timer != nil {
			b.timer.Stop()
		}
		keys = append(keys, k)
	}
	c.mu.Unlock()
	for _, k := range keys {
		c.flushKey(k)
	}
}

func (c *Correlator) flushKey(key string) {
	c.mu.Lock()
	b := c.buckets[key]
	delete(c.buckets, key)
	c.mu.Unlock()
	if b == nil || len(b.alerts) == 0 {
		return
	}
	c.logger.Info("flushing incident",
		zap.String("group", key),
		zap.Int("alerts", len(b.alerts)),
	)
	c.flush(b.alerts)
}

// groupKey decides what counts as "the same incident". Node-scoped alerts cluster
// by node (a failing node cascades across namespaces); everything else clusters
// by namespace within a cluster.
func groupKey(p *pb.AlertPayload) string {
	if p.Target != nil && p.Target.Node != "" {
		return p.ClusterId + "|node|" + p.Target.Node
	}
	return p.ClusterId + "|ns|" + p.Namespace
}

// Representative picks the alert a grouped notification should center on: the
// highest-severity alert, falling back to the first.
func Representative(alerts []*pb.AlertPayload) *pb.AlertPayload {
	if len(alerts) == 0 {
		return nil
	}
	best := alerts[0]
	for _, a := range alerts[1:] {
		if severityRank(a.Severity) > severityRank(best.Severity) {
			best = a
		}
	}
	return best
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
