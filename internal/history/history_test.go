package history

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/alertkey"
	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

func TestRecord_RoundTrip(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	h := New(st, time.Hour, zap.NewNop())

	rep := &pb.AlertPayload{ClusterId: "c1", AlertName: "OOM", Namespace: "ns", PodName: "p1", Severity: "critical", FiredAt: 1000}
	other := &pb.AlertPayload{ClusterId: "c1", AlertName: "DiskFull", Namespace: "ns"}
	an := &evaluator.Analysis{RootCause: "oom", Confidence: "high", Grounding: "stated"}

	h.Record(context.Background(), rep, an, []*pb.AlertPayload{rep, other})

	rec, ok, err := h.Get(context.Background(), alertkey.ID(rep))
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if rec.AlertName != "OOM" || rec.AlertCount != 2 || rec.Analysis.RootCause != "oom" {
		t.Errorf("unexpected record: %+v", rec)
	}
	if len(rec.RelatedAlerts) != 1 || rec.RelatedAlerts[0] != "DiskFull" {
		t.Errorf("related alerts wrong: %v", rec.RelatedAlerts)
	}
}

func TestList(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	h := New(st, time.Hour, zap.NewNop())

	h.Record(context.Background(), &pb.AlertPayload{ClusterId: "c", AlertName: "A", FiredAt: 1}, &evaluator.Analysis{}, nil)
	h.Record(context.Background(), &pb.AlertPayload{ClusterId: "c", AlertName: "B", FiredAt: 2}, &evaluator.Analysis{}, nil)

	recs, err := h.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Errorf("List len = %d, want 2", len(recs))
	}
}

// TestNilStore confirms a nil *Store is a safe no-op (disabled history).
func TestNilStore(t *testing.T) {
	var h *Store
	h.Record(context.Background(), &pb.AlertPayload{}, nil, nil) // must not panic
	if _, ok, _ := h.Get(context.Background(), "x"); ok {
		t.Error("nil store Get should report not found")
	}
	if recs, _ := h.List(context.Background()); recs != nil {
		t.Error("nil store List should be nil")
	}
}
