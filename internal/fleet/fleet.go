// Package fleet answers the one question the monitored clusters cannot answer
// about themselves: is the collector still alive?
//
// A collector reports liveness with a periodic Heartbeat RPC. The brain records
// the timestamp in the shared store and a watchdog notices when beats stop.
// This has to live here, outside the monitored cluster: an `absent(up{...})`
// rule in the cluster's own Prometheus only fires while that Prometheus is
// running, so a dead node, a deleted VM, or a severed network takes the alarm
// down with the thing it was supposed to alarm about.
//
// The roster deliberately shrinks. A decommissioned cluster must stop paging,
// and it does so through three independent paths: the tenant is revoked or
// removed from the tenants file (the GitOps offboarding step), the collector
// sends a final shutting_down beat, or — if neither happened — the record ages
// out of the store after RosterTTL.
package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// storePrefix namespaces heartbeat records in the shared store.
const storePrefix = "fleet:heartbeat:"

// State is the persisted view of one collector, written on every heartbeat and
// read by the watchdog. It is intentionally small and JSON-encoded: the store
// is a byte-oriented KV, and a handful of clusters makes scan cost irrelevant.
type State struct {
	ClusterID       string `json:"cluster_id"`
	LastSeen        int64  `json:"last_seen"`        // unix seconds
	StartedAt       int64  `json:"started_at"`       // collector process start
	IntervalSeconds int32  `json:"interval_seconds"` // collector's beat period
	Version         string `json:"version"`          // collector version
	AlertsForwarded int64  `json:"alerts_forwarded"` // cumulative, since StartedAt
	Retired         bool   `json:"retired"`          // graceful shutdown announced
	Down            bool   `json:"down"`             // watchdog has already paged
	DownNotifiedAt  int64  `json:"down_notified_at"` // unix seconds, 0 when never

	// PipelineLastSeen is when a Watchdog alert last completed the trip from
	// the cluster's Prometheus through its AlertManager to the collector. 0
	// means the operator never routed one, which is never treated as a fault.
	PipelineLastSeen int64 `json:"pipeline_last_seen"`
	// PipelineDown records that the broken-pipeline notification already went
	// out, so a continuing fault does not re-page on every tick.
	PipelineDown bool `json:"pipeline_down"`
}

// PipelineConfigured reports whether the cluster ever proved its alerting
// path works. Until it does, the brain stays silent about it: an operator who
// has not opted in must not be paged about a probe they never wired up.
func (s State) PipelineConfigured() bool { return s.PipelineLastSeen > 0 }

// PipelineAge returns how long ago the alerting path last proved itself.
func (s State) PipelineAge(now time.Time) time.Duration {
	return now.Sub(time.Unix(s.PipelineLastSeen, 0))
}

// Age returns how long ago the last beat arrived, relative to now.
func (s State) Age(now time.Time) time.Duration {
	return now.Sub(time.Unix(s.LastSeen, 0))
}

// staleAfter is the silence that makes a collector "down". Derived from the
// collector's own reported interval rather than a brain-side constant, so a
// cluster that beats every 5 minutes is not paged after 90 seconds. The
// multiplier tolerates one missed beat plus scheduling jitter; the floor keeps
// a misconfigured interval of 0 from making every beat instantly stale.
func (s State) staleAfter(multiplier float64, floor time.Duration) time.Duration {
	d := time.Duration(float64(s.IntervalSeconds) * float64(time.Second) * multiplier)
	if d < floor {
		return floor
	}
	return d
}

// key returns the store key holding a cluster's heartbeat record.
func key(clusterID string) string { return storePrefix + clusterID }

// marshal/unmarshal keep the JSON encoding in one place so the tracker and the
// watchdog cannot drift on the wire shape.
func marshal(s State) ([]byte, error) { return json.Marshal(s) }

func unmarshal(b []byte) (State, error) {
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("fleet: decode heartbeat state: %w", err)
	}
	return s, nil
}

// Status is the watchdog's verdict for one cluster on one tick.
type Status int

const (
	// StatusUp means beats are arriving within the staleness threshold.
	StatusUp Status = iota
	// StatusDown means beats stopped and the cluster was not retired.
	StatusDown
	// StatusRecovered means beats resumed after a StatusDown notification.
	StatusRecovered
	// StatusRetired means the cluster left the fleet deliberately (revoked
	// tenant or announced shutdown) and must never page.
	StatusRetired
	// StatusPipelineDown means the collector is alive and reporting, but the
	// cluster's own alerting path stopped delivering. Alerts raised there are
	// being lost — a worse failure than a dead collector, and invisible
	// without the Watchdog probe.
	StatusPipelineDown
	// StatusPipelineRecovered means that path started delivering again.
	StatusPipelineRecovered
)

func (s Status) String() string {
	switch s {
	case StatusUp:
		return "up"
	case StatusDown:
		return "down"
	case StatusRecovered:
		return "recovered"
	case StatusRetired:
		return "retired"
	case StatusPipelineDown:
		return "pipeline_down"
	case StatusPipelineRecovered:
		return "pipeline_recovered"
	default:
		return "unknown"
	}
}

// ctxTimeout bounds every store call the package makes. Heartbeat handling sits
// on the collector's request path and the watchdog runs on a ticker; neither
// may block on a wedged Redis.
const ctxTimeout = 5 * time.Second

func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, ctxTimeout)
}
