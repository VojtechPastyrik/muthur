package llmcache

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/embed"
	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

func testPayload() *pb.AlertPayload {
	return &pb.AlertPayload{ClusterId: "cluster-a", AlertName: "PodCrash", Namespace: "default", PodName: "api-1"}
}

func newCache(enabled bool) *Cache {
	return New(enabled, 30, store.NewMemory(), nil, false, 0.95, zap.NewNop())
}

func TestCacheHitMiss(t *testing.T) {
	c := newCache(true)
	p := testPayload()
	ctx := context.Background()

	if _, ok := c.Get(ctx, p); ok {
		t.Fatalf("expected miss on empty cache")
	}

	a := &evaluator.Analysis{Severity: "high", RootCause: "oom"}
	c.Set(ctx, p, a)

	got, ok := c.Get(ctx, p)
	if !ok {
		t.Fatalf("expected hit after Set")
	}
	if got.Severity != "high" || got.RootCause != "oom" {
		t.Fatalf("unexpected analysis: %+v", got)
	}
}

func TestCacheDisabledNoop(t *testing.T) {
	c := newCache(false)
	p := testPayload()
	ctx := context.Background()
	c.Set(ctx, p, &evaluator.Analysis{Severity: "high"})
	if _, ok := c.Get(ctx, p); ok {
		t.Fatalf("expected miss when cache disabled")
	}
}

func TestCacheKeyDistinguishesAlerts(t *testing.T) {
	c := newCache(true)
	ctx := context.Background()
	p1 := testPayload()
	p2 := testPayload()
	p2.PodName = "api-2"

	c.Set(ctx, p1, &evaluator.Analysis{Severity: "low"})
	if _, ok := c.Get(ctx, p2); ok {
		t.Fatalf("different pod_name should not collide (exact layer)")
	}
}

func TestCacheSetNilAnalysisNoop(t *testing.T) {
	c := newCache(true)
	p := testPayload()
	ctx := context.Background()
	c.Set(ctx, p, nil)
	if _, ok := c.Get(ctx, p); ok {
		t.Fatalf("nil analysis must not be cached")
	}
}

// TestSemanticHit verifies that a different pod with an identical signature
// reuses the analysis via the semantic layer even though the exact key differs.
func TestSemanticHit(t *testing.T) {
	c := New(true, 30, store.NewMemory(), embed.NewHashEmbedder(256), true, 0.95, zap.NewNop())
	ctx := context.Background()

	p1 := testPayload()
	c.Set(ctx, p1, &evaluator.Analysis{Severity: "high", RootCause: "crashloop"})

	p2 := testPayload()
	p2.PodName = "api-2" // different exact key, same signature
	got, ok := c.Get(ctx, p2)
	if !ok {
		t.Fatalf("expected semantic hit for near-duplicate alert")
	}
	if got.RootCause != "crashloop" {
		t.Fatalf("unexpected analysis: %+v", got)
	}
}

// TestSemanticMissDifferentAlert ensures unrelated alerts don't falsely match.
func TestSemanticMissDifferentAlert(t *testing.T) {
	c := New(true, 30, store.NewMemory(), embed.NewHashEmbedder(256), true, 0.95, zap.NewNop())
	ctx := context.Background()

	p1 := testPayload()
	c.Set(ctx, p1, &evaluator.Analysis{Severity: "high", RootCause: "crashloop"})

	p2 := &pb.AlertPayload{ClusterId: "cluster-a", AlertName: "DiskFull", Namespace: "storage", PodName: "x", Severity: "warning"}
	if _, ok := c.Get(ctx, p2); ok {
		t.Fatalf("unrelated alert should not semantically match")
	}
}
