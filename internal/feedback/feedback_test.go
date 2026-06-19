package feedback

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

func TestLinksDisabledWithoutPublicURL(t *testing.T) {
	m := New(store.NewMemory(), "", 3, zap.NewNop())
	if m.LinksEnabled() {
		t.Fatal("links should be disabled without public URL")
	}
	up, down := m.Record(context.Background(), &pb.AlertPayload{AlertName: "x"}, &evaluator.Analysis{})
	if up != "" || down != "" {
		t.Fatal("no links should be produced when disabled")
	}
}

func TestFeedbackRoundTrip(t *testing.T) {
	m := New(store.NewMemory(), "https://muthur.example.com/", 3, zap.NewNop())
	ctx := context.Background()

	payload := &pb.AlertPayload{ClusterId: "a", AlertName: "HighMemory", Namespace: "default", PodName: "p1", FiredAt: 100}
	analysis := &evaluator.Analysis{RootCause: "memory leak"}

	up, down := m.Record(ctx, payload, analysis)
	if up == "" || down == "" {
		t.Fatal("expected feedback links")
	}
	if !strings.Contains(up, "verdict=useful") || !strings.Contains(down, "verdict=wrong") {
		t.Fatalf("unexpected links: %s / %s", up, down)
	}

	// Simulate the operator clicking "useful".
	u, _ := url.Parse(up)
	req := httptest.NewRequest(http.MethodGet, u.String(), nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("feedback handler returned %d", rec.Code)
	}

	// The verdict should now surface as a few-shot example for this alert.
	examples := m.Examples(ctx, payload)
	if len(examples) != 1 {
		t.Fatalf("expected 1 example, got %d", len(examples))
	}
	if examples[0].Verdict != "useful" || examples[0].Analysis.RootCause != "memory leak" {
		t.Fatalf("unexpected example: %+v", examples[0])
	}
}

func TestFeedbackBadVerdict(t *testing.T) {
	m := New(store.NewMemory(), "https://x.example.com", 3, zap.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/feedback?id=abc&verdict=bogus", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad verdict, got %d", rec.Code)
	}
}
