// Package history persists incident records — the analysis muthur produced for
// an alert or correlated group, keyed by the shared alertkey ID. This is the
// foundation other read paths build on (Grafana dashboards over the structured
// "incident recorded" log, a future MCP server, agentic recurrence queries).
//
// It is deliberately thin: one record per incident under "incident:<id>", with
// a TTL, on the existing store abstraction. Recording never blocks delivery —
// a store failure is logged and swallowed.
package history

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/alertkey"
	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	"github.com/VojtechPastyrik/muthur/internal/metrics"
	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// keyPrefix namespaces incident records in the store.
const keyPrefix = "incident:"

// Record is the persisted incident: the analysis plus the identity needed to
// query and cross-reference it (the ID matches the feedback verdict ID).
type Record struct {
	ID            string              `json:"id"`
	ClusterID     string              `json:"cluster_id"`
	AlertName     string              `json:"alert_name"`
	Namespace     string              `json:"namespace"`
	Severity      string              `json:"severity"`
	FiredAt       int64               `json:"fired_at"`
	AlertCount    int                 `json:"alert_count"`
	RelatedAlerts []string            `json:"related_alerts,omitempty"`
	Analysis      *evaluator.Analysis `json:"analysis,omitempty"`
	RecordedAt    int64               `json:"recorded_at"`
}

// Store records and reads incident history. A nil *Store is safe and a no-op,
// so callers can hold a disabled store without nil checks at every call site.
type Store struct {
	store  store.Store
	ttl    time.Duration
	logger *zap.Logger
}

// New builds a history Store. A non-positive ttl falls back to 30 days.
func New(st store.Store, ttl time.Duration, logger *zap.Logger) *Store {
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	return &Store{store: st, ttl: ttl, logger: logger}
}

// Record persists the incident for rep (the representative alert) and its group.
// alerts may be a single-element slice for a non-correlated alert. A nil Store,
// nil analysis, or store error never propagates — history is best-effort.
func (s *Store) Record(ctx context.Context, rep *pb.AlertPayload, analysis *evaluator.Analysis, alerts []*pb.AlertPayload) {
	if s == nil || rep == nil {
		return
	}

	rec := Record{
		ID:         alertkey.ID(rep),
		ClusterID:  rep.ClusterId,
		AlertName:  rep.AlertName,
		Namespace:  rep.Namespace,
		Severity:   rep.Severity,
		FiredAt:    rep.FiredAt,
		AlertCount: len(alerts),
		Analysis:   analysis,
		RecordedAt: time.Now().Unix(),
	}
	if rec.AlertCount == 0 {
		rec.AlertCount = 1
	}
	for _, a := range alerts {
		if a != rep {
			rec.RelatedAlerts = append(rec.RelatedAlerts, a.AlertName)
		}
	}

	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if err := s.store.Set(ctx, keyPrefix+rec.ID, b, s.ttl); err != nil {
		s.logger.Warn("incident history record error", zap.Error(err))
		return
	}

	metrics.IncidentsRecorded.Inc()
	// Structured log so the history is immediately queryable in Grafana/Loki
	// even before any richer read path (MCP) exists.
	s.logger.Info("incident recorded",
		zap.String("incident_id", rec.ID),
		zap.String("cluster_id", rec.ClusterID),
		zap.String("alert_name", rec.AlertName),
		zap.String("namespace", rec.Namespace),
		zap.String("severity", rec.Severity),
		zap.Int("alert_count", rec.AlertCount),
	)
}

// Get returns the incident record for id, if present and unexpired.
func (s *Store) Get(ctx context.Context, id string) (*Record, bool, error) {
	if s == nil {
		return nil, false, nil
	}
	data, ok, err := s.store.Get(ctx, keyPrefix+id)
	if err != nil || !ok {
		return nil, ok, err
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, false, err
	}
	return &rec, true, nil
}

// List returns all live incident records. Order is unspecified.
func (s *Store) List(ctx context.Context) ([]*Record, error) {
	if s == nil {
		return nil, nil
	}
	vals, err := s.store.ListByPrefix(ctx, keyPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]*Record, 0, len(vals))
	for _, raw := range vals {
		var rec Record
		if err := json.Unmarshal(raw, &rec); err == nil {
			out = append(out, &rec)
		}
	}
	return out, nil
}
