package fleet

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/metrics"
	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// Errors returned by Record. They mirror the ingest handler's vocabulary so the
// transport shims (gRPC, signed HTTP) map them to status codes the same way.
var (
	// ErrNoIdentity means the call arrived without a verified client identity.
	ErrNoIdentity = errors.New("fleet: heartbeat without verified identity")
	// ErrForbidden means the body's cluster_id contradicts the certificate.
	ErrForbidden = errors.New("fleet: heartbeat cluster_id does not match certificate")
)

// Tracker records heartbeats. It is the write half of the package; the
// Watchdog is the read half. Both talk only to the Store, so a multi-replica
// brain behind Redis shares one fleet view.
type Tracker struct {
	store     store.Store
	rosterTTL time.Duration
	logger    *zap.Logger
}

// NewTracker returns a Tracker writing records under rosterTTL. The TTL is the
// backstop against a roster that only grows: a cluster nobody ever revoked
// disappears on its own once it has been silent this long.
func NewTracker(s store.Store, rosterTTL time.Duration, logger *zap.Logger) *Tracker {
	return &Tracker{store: s, rosterTTL: rosterTTL, logger: logger}
}

// Record persists a heartbeat. clusterID comes from the verified certificate,
// never from the request body — the body's cluster_id is only cross-checked,
// exactly as Ingest does, so a compromised collector cannot report liveness on
// behalf of another tenant (or mask another tenant's outage by keeping its
// record fresh).
func (t *Tracker) Record(ctx context.Context, certClusterID string, req *pb.HeartbeatRequest) error {
	if certClusterID == "" {
		return ErrNoIdentity
	}
	if body := req.GetClusterId(); body != "" && body != certClusterID {
		return ErrForbidden
	}

	now := time.Now()
	st := State{
		ClusterID:        certClusterID,
		LastSeen:         now.Unix(),
		StartedAt:        req.GetStartedAt(),
		IntervalSeconds:  req.GetIntervalSeconds(),
		Version:          req.GetCollectorVersion(),
		AlertsForwarded:  req.GetAlertsForwarded(),
		Retired:          req.GetShuttingDown(),
		PipelineLastSeen: req.GetPipelineLastSeen(),
	}

	// Carry the previous down-state forward so the watchdog can tell a first
	// beat after an outage (→ recovery notice) from steady-state liveness.
	if prev, ok := t.load(ctx, certClusterID); ok {
		st.Down = prev.Down
		st.DownNotifiedAt = prev.DownNotifiedAt
		st.PipelineDown = prev.PipelineDown
	}

	if err := t.save(ctx, st); err != nil {
		return err
	}

	metrics.Heartbeats.WithLabelValues(certClusterID).Inc()
	if st.PipelineConfigured() {
		metrics.CollectorPipelineLastSeen.WithLabelValues(certClusterID).Set(float64(st.PipelineLastSeen))
	}
	metrics.CollectorLastSeen.WithLabelValues(certClusterID).Set(float64(st.LastSeen))
	if !st.Retired {
		metrics.CollectorUp.WithLabelValues(certClusterID).Set(1)
	}

	if st.Retired {
		// A graceful goodbye is worth a log line: it is the difference between
		// "someone uninstalled this" and "this cluster fell off the network",
		// and that distinction is invisible later from the absence of beats.
		t.logger.Info("collector announced shutdown; cluster retired from watchdog",
			zap.String("cluster_id", certClusterID),
			zap.String("version", st.Version),
		)
	}
	return nil
}

func (t *Tracker) load(ctx context.Context, clusterID string) (State, bool) {
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	b, ok, err := t.store.Get(cctx, key(clusterID))
	if err != nil || !ok {
		return State{}, false
	}
	st, err := unmarshal(b)
	if err != nil {
		return State{}, false
	}
	return st, true
}

func (t *Tracker) save(ctx context.Context, st State) error {
	b, err := marshal(st)
	if err != nil {
		return err
	}
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	return t.store.Set(cctx, key(st.ClusterID), b, t.rosterTTL)
}
