package fleet

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	"github.com/VojtechPastyrik/muthur/internal/metrics"
	"github.com/VojtechPastyrik/muthur/internal/store"
)

// Event is one state transition the watchdog observed. Only transitions are
// emitted — a cluster that stays down produces exactly one Event, not one per
// tick, so an outage over a weekend is a single notification rather than a
// thousand.
type Event struct {
	Status Status
	State  State
	// Age is how long the collector had been silent when the verdict was made.
	Age time.Duration
}

// NotifyFunc delivers an Event. The pipeline supplies one that renders a
// synthetic alert through the normal routing + notifier path, so collector
// outages reach the same receivers as everything else.
type NotifyFunc func(Event)

// WatchdogConfig tunes the staleness verdict.
type WatchdogConfig struct {
	// Enabled gates the whole watchdog. Heartbeats are still recorded and
	// exported as metrics when false — only the notifications stop.
	Enabled bool
	// Interval is how often the roster is scanned.
	Interval time.Duration
	// StaleMultiplier multiplies the collector's own reported beat interval to
	// get the staleness threshold. 3.0 tolerates two missed beats.
	StaleMultiplier float64
	// StaleFloor is the minimum staleness threshold, guarding against a
	// collector that reports a tiny (or zero) interval.
	StaleFloor time.Duration
	// PipelineStale is how long the cluster's alerting path may go without
	// delivering a Watchdog alert before it counts as broken. Fixed rather
	// than derived: the cadence belongs to the cluster's AlertManager
	// (repeat_interval), which the collector cannot see. The default
	// tolerates a 5m repeat_interval plus jitter.
	PipelineStale time.Duration
}

// Watchdog scans the heartbeat roster and reports collectors that went silent.
type Watchdog struct {
	store   store.Store
	tenants auth.TenantsProvider
	notify  NotifyFunc
	cfg     WatchdogConfig
	logger  *zap.Logger

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewWatchdog wires a watchdog. tenants is the authoritative fleet roster: a
// cluster absent from it (removed) or flagged revoked has been decommissioned
// and is purged rather than paged.
func NewWatchdog(s store.Store, tenants auth.TenantsProvider, notify NotifyFunc, cfg WatchdogConfig, logger *zap.Logger) *Watchdog {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.StaleMultiplier <= 0 {
		cfg.StaleMultiplier = 3
	}
	if cfg.StaleFloor <= 0 {
		cfg.StaleFloor = 2 * time.Minute
	}
	if cfg.PipelineStale <= 0 {
		cfg.PipelineStale = 10 * time.Minute
	}
	return &Watchdog{
		store:   s,
		tenants: tenants,
		notify:  notify,
		cfg:     cfg,
		logger:  logger,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

// Start runs the scan loop until Stop. It returns immediately.
func (w *Watchdog) Start() {
	if !w.cfg.Enabled {
		w.logger.Info("collector watchdog disabled; heartbeats recorded as metrics only")
		close(w.doneCh)
		return
	}
	w.logger.Info("collector watchdog started",
		zap.Duration("interval", w.cfg.Interval),
		zap.Float64("stale_multiplier", w.cfg.StaleMultiplier),
		zap.Duration("stale_floor", w.cfg.StaleFloor),
	)
	go w.loop()
}

// Stop halts the scan loop and waits for the in-flight tick to finish.
func (w *Watchdog) Stop() {
	if !w.cfg.Enabled {
		return
	}
	close(w.stopCh)
	<-w.doneCh
}

func (w *Watchdog) loop() {
	defer close(w.doneCh)
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.Scan(context.Background(), time.Now())
		}
	}
}

// Scan performs one pass over the roster. Exported for tests and for an
// on-demand check; now is injected so staleness is deterministic under test.
func (w *Watchdog) Scan(ctx context.Context, now time.Time) {
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	raw, err := w.store.ListByPrefix(cctx, storePrefix)
	if err != nil {
		w.logger.Warn("watchdog roster scan failed", zap.Error(err))
		return
	}

	tenants := w.tenants.Current()
	for _, b := range raw {
		st, err := unmarshal(b)
		if err != nil {
			w.logger.Warn("watchdog skipping undecodable heartbeat record", zap.Error(err))
			continue
		}
		w.evaluate(ctx, now, tenants, st)
	}
}

// evaluate decides one cluster's fate for this tick.
func (w *Watchdog) evaluate(ctx context.Context, now time.Time, tenants *auth.Tenants, st State) {
	// Decommission wins over everything. A tenant that was removed from the
	// config or flagged revoked is gone on purpose: drop the record and the
	// metric series so neither a page nor a stale `muthur_collector_up 0`
	// outlives the cluster.
	if tenants != nil {
		if tenant, ok := tenants.Lookup(st.ClusterID); !ok || tenant.Revoked {
			w.retire(ctx, st, "tenant revoked or removed")
			return
		}
	}

	// Announced shutdown: the collector said goodbye, so silence is expected.
	if st.Retired {
		w.retire(ctx, st, "collector announced shutdown")
		return
	}

	age := st.Age(now)
	threshold := st.staleAfter(w.cfg.StaleMultiplier, w.cfg.StaleFloor)

	// The pipeline verdict is independent of the liveness verdict, and only
	// meaningful while the collector is still reporting: once the beats stop,
	// a stale probe says nothing new, so the down notification covers both.
	if age <= threshold {
		w.evaluatePipeline(ctx, now, st)
	}

	switch {
	case age > threshold && !st.Down:
		st.Down = true
		st.DownNotifiedAt = now.Unix()
		w.persist(ctx, st)
		metrics.CollectorUp.WithLabelValues(st.ClusterID).Set(0)
		w.logger.Error("collector is down",
			zap.String("cluster_id", st.ClusterID),
			zap.Duration("silent_for", age.Truncate(time.Second)),
			zap.Duration("threshold", threshold),
			zap.String("version", st.Version),
		)
		w.emit(Event{Status: StatusDown, State: st, Age: age})

	case age <= threshold && st.Down:
		st.Down = false
		st.DownNotifiedAt = 0
		w.persist(ctx, st)
		metrics.CollectorUp.WithLabelValues(st.ClusterID).Set(1)
		w.logger.Info("collector recovered",
			zap.String("cluster_id", st.ClusterID),
			zap.String("version", st.Version),
		)
		w.emit(Event{Status: StatusRecovered, State: st, Age: age})

	case age <= threshold:
		// Steady state. Re-assert the gauge so a brain restart repopulates the
		// series without waiting for the next beat.
		metrics.CollectorUp.WithLabelValues(st.ClusterID).Set(1)
		metrics.CollectorLastSeen.WithLabelValues(st.ClusterID).Set(float64(st.LastSeen))
	}
}

// evaluatePipeline decides whether the cluster's own alerting path is still
// delivering. A collector can be perfectly healthy while its cluster's
// Prometheus is crashlooping or its AlertManager drops everything — in which
// case alerts raised there are being lost, silently. This is the only signal
// that separates those two worlds.
func (w *Watchdog) evaluatePipeline(ctx context.Context, now time.Time, st State) {
	if !st.PipelineConfigured() {
		// Watchdog was never routed to this collector. Not a fault — an
		// operator who did not opt in must not be paged about it.
		return
	}

	stale := st.PipelineAge(now) > w.cfg.PipelineStale
	switch {
	case stale && !st.PipelineDown:
		st.PipelineDown = true
		w.persist(ctx, st)
		w.logger.Error("cluster alerting pipeline stopped delivering",
			zap.String("cluster_id", st.ClusterID),
			zap.Duration("silent_for", st.PipelineAge(now).Truncate(time.Second)),
			zap.Duration("threshold", w.cfg.PipelineStale),
		)
		w.emit(Event{Status: StatusPipelineDown, State: st, Age: st.PipelineAge(now)})

	case !stale && st.PipelineDown:
		st.PipelineDown = false
		w.persist(ctx, st)
		w.logger.Info("cluster alerting pipeline recovered",
			zap.String("cluster_id", st.ClusterID))
		w.emit(Event{Status: StatusPipelineRecovered, State: st})
	}
}

// retire removes a cluster from the roster permanently. The record is deleted
// rather than kept with a flag: the store TTL would otherwise keep resurrecting
// it in scans, and a deleted metric series is what makes a decommissioned
// cluster vanish from dashboards instead of sitting at 0 forever.
func (w *Watchdog) retire(ctx context.Context, st State, reason string) {
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	if err := w.store.Delete(cctx, key(st.ClusterID)); err != nil {
		w.logger.Warn("failed to purge retired collector record",
			zap.String("cluster_id", st.ClusterID), zap.Error(err))
		return
	}
	metrics.CollectorUp.DeleteLabelValues(st.ClusterID)
	metrics.CollectorLastSeen.DeleteLabelValues(st.ClusterID)
	metrics.CollectorPipelineLastSeen.DeleteLabelValues(st.ClusterID)
	w.logger.Info("collector retired from fleet roster",
		zap.String("cluster_id", st.ClusterID),
		zap.String("reason", reason),
	)
	// A cluster that was already paged as down and is now being retired gets a
	// closing notification, so the open 🔴 in the channel does not dangle.
	if st.Down {
		w.emit(Event{Status: StatusRetired, State: st})
	}
}

func (w *Watchdog) persist(ctx context.Context, st State) {
	b, err := marshal(st)
	if err != nil {
		w.logger.Warn("failed to encode heartbeat state", zap.Error(err))
		return
	}
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	// Preserve the remaining roster TTL semantics by rewriting with the same
	// policy the tracker uses: a record refreshed only by the watchdog must
	// still age out if the collector never comes back.
	if err := w.store.Set(cctx, key(st.ClusterID), b, rosterTTLFor(st)); err != nil {
		w.logger.Warn("failed to persist heartbeat state",
			zap.String("cluster_id", st.ClusterID), zap.Error(err))
	}
}

// rosterTTLFor keeps a down cluster's record alive long enough for the recovery
// path to see the Down flag, but not forever. Seven days matches the tracker
// default and is far longer than any realistic outage an operator would want a
// single page for.
func rosterTTLFor(State) time.Duration { return 7 * 24 * time.Hour }

func (w *Watchdog) emit(ev Event) {
	if w.notify == nil {
		return
	}
	w.notify(ev)
}
