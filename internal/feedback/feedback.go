// Package feedback closes the loop on Claude's analyses. Each notification can
// carry two links — "useful" and "wrong" — that point back at muthur-central's
// /feedback endpoint. When an operator clicks one, the verdict is persisted and
// later replayed into the prompt as a few-shot signal (see evaluator.Example),
// so evaluations improve per-cluster over time.
//
// Feedback links are emitted only when a public base URL is configured (the
// links must be reachable from the operator's browser). The few-shot replay and
// verdict storage work regardless.
package feedback

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/alertkey"
	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	"github.com/VojtechPastyrik/muthur/internal/metrics"
	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

type Manager struct {
	store      store.Store
	publicURL  string // trailing slash trimmed; empty disables links
	pendingTTL time.Duration
	verdictTTL time.Duration
	fewShot    int
	logger     *zap.Logger
}

type pendingEntry struct {
	ClusterID string              `json:"cluster_id"`
	AlertName string              `json:"alert_name"`
	Namespace string              `json:"namespace"`
	Analysis  *evaluator.Analysis `json:"analysis"`
}

type verdictEntry struct {
	AlertName string              `json:"alert_name"`
	Verdict   string              `json:"verdict"`
	Analysis  *evaluator.Analysis `json:"analysis"`
	TS        int64               `json:"ts"`
}

// New builds a feedback Manager. publicURL is muthur-central's externally
// reachable base URL (e.g. https://muthur.example.com); when empty, links are
// not emitted but verdict storage and few-shot replay still function.
func New(st store.Store, publicURL string, fewShot int, logger *zap.Logger) *Manager {
	if fewShot <= 0 {
		fewShot = 3
	}
	return &Manager{
		store:      st,
		publicURL:  trimSlash(publicURL),
		pendingTTL: 7 * 24 * time.Hour,
		verdictTTL: 30 * 24 * time.Hour,
		fewShot:    fewShot,
		logger:     logger,
	}
}

// LinksEnabled reports whether feedback links can be emitted.
func (m *Manager) LinksEnabled() bool { return m.publicURL != "" }

// Record stores the analysis behind a deterministic feedback ID so a later
// /feedback click can resolve it, and returns the two click URLs. When links
// are disabled it records nothing and returns empty strings.
func (m *Manager) Record(ctx context.Context, payload *pb.AlertPayload, analysis *evaluator.Analysis) (upURL, downURL string) {
	if !m.LinksEnabled() || analysis == nil {
		return "", ""
	}
	id := m.id(payload)
	entry := pendingEntry{
		ClusterID: payload.ClusterId,
		AlertName: payload.AlertName,
		Namespace: payload.Namespace,
		Analysis:  analysis,
	}
	if b, err := json.Marshal(entry); err == nil {
		if err := m.store.Set(ctx, "fb:pending:"+id, b, m.pendingTTL); err != nil {
			m.logger.Warn("feedback record error", zap.Error(err))
			return "", ""
		}
	}
	base := m.publicURL + "/feedback?id=" + id + "&verdict="
	return base + "useful", base + "wrong"
}

// Examples returns recent operator verdicts for this alert name, newest first,
// to inject as few-shot guidance into the next evaluation.
func (m *Manager) Examples(ctx context.Context, payload *pb.AlertPayload) []evaluator.Example {
	vals, err := m.store.ListByPrefix(ctx, "fb:verdict:"+alertHash(payload.AlertName)+":")
	if err != nil || len(vals) == 0 {
		return nil
	}
	entries := make([]verdictEntry, 0, len(vals))
	for _, raw := range vals {
		var e verdictEntry
		if err := json.Unmarshal(raw, &e); err == nil {
			entries = append(entries, e)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].TS > entries[j].TS })
	if len(entries) > m.fewShot {
		entries = entries[:m.fewShot]
	}
	out := make([]evaluator.Example, 0, len(entries))
	for _, e := range entries {
		out = append(out, evaluator.Example{AlertName: e.AlertName, Verdict: e.Verdict, Analysis: e.Analysis})
	}
	return out
}

// ServeHTTP handles GET /feedback?id=<id>&verdict=useful|wrong. It resolves the
// pending analysis, stores the verdict for few-shot replay, and returns a small
// confirmation page.
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	verdict := r.URL.Query().Get("verdict")
	if id == "" || (verdict != "useful" && verdict != "wrong") {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	data, ok, err := m.store.Get(r.Context(), "fb:pending:"+id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "feedback link expired or unknown", http.StatusNotFound)
		return
	}

	var pending pendingEntry
	if err := json.Unmarshal(data, &pending); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	entry := verdictEntry{
		AlertName: pending.AlertName,
		Verdict:   verdict,
		Analysis:  pending.Analysis,
		TS:        time.Now().Unix(),
	}
	if b, err := json.Marshal(entry); err == nil {
		key := "fb:verdict:" + alertHash(pending.AlertName) + ":" + id
		if err := m.store.Set(r.Context(), key, b, m.verdictTTL); err != nil {
			m.logger.Warn("feedback store error", zap.Error(err))
		}
	}

	metrics.Feedback.WithLabelValues(verdict).Inc()
	m.logger.Info("feedback recorded",
		zap.String("alert_name", pending.AlertName),
		zap.String("verdict", verdict),
	)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body style=\"font-family:sans-serif\"><h2>Thanks</h2><p>Recorded feedback <b>%s</b> for alert <b>%s</b>. muthur will use this to improve future analyses.</p></body></html>",
		verdict, pending.AlertName)
}

// id is the shared per-alert identifier; the same value keys the incident
// record in internal/history, so feedback and incident cross-reference.
func (m *Manager) id(payload *pb.AlertPayload) string {
	return alertkey.ID(payload)
}

func alertHash(name string) string {
	h := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%x", h)[:12]
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
