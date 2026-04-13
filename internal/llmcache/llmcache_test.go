package llmcache

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

func testPayload() *pb.AlertPayload {
	return &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "PodCrash",
		Namespace: "default",
		PodName:   "api-1",
	}
}

func TestCacheHitMiss(t *testing.T) {
	c := New(true, 30, zap.NewNop())
	p := testPayload()

	if _, ok := c.Get(p); ok {
		t.Fatalf("expected miss on empty cache")
	}

	a := &evaluator.Analysis{Severity: "high", RootCause: "oom"}
	c.Set(p, a)

	got, ok := c.Get(p)
	if !ok {
		t.Fatalf("expected hit after Set")
	}
	if got.Severity != "high" || got.RootCause != "oom" {
		t.Fatalf("unexpected analysis: %+v", got)
	}
}

func TestCacheDisabledNoop(t *testing.T) {
	c := New(false, 30, zap.NewNop())
	p := testPayload()
	c.Set(p, &evaluator.Analysis{Severity: "high"})
	if _, ok := c.Get(p); ok {
		t.Fatalf("expected miss when cache disabled")
	}
}

func TestCacheExpiry(t *testing.T) {
	c := New(true, 30, zap.NewNop())
	p := testPayload()
	c.Set(p, &evaluator.Analysis{Severity: "high"})

	// Manually expire the entry.
	key := c.key(p)
	val, _ := c.store.Load(key)
	val.(*entry).expiresAt = time.Now().Add(-time.Second)

	if _, ok := c.Get(p); ok {
		t.Fatalf("expected miss after expiry")
	}
}

func TestCacheKeyDistinguishesAlerts(t *testing.T) {
	c := New(true, 30, zap.NewNop())
	p1 := testPayload()
	p2 := testPayload()
	p2.PodName = "api-2"

	c.Set(p1, &evaluator.Analysis{Severity: "low"})
	if _, ok := c.Get(p2); ok {
		t.Fatalf("different pod_name should not collide")
	}
}

func TestCacheSetNilAnalysisNoop(t *testing.T) {
	c := New(true, 30, zap.NewNop())
	p := testPayload()
	c.Set(p, nil)
	if _, ok := c.Get(p); ok {
		t.Fatalf("nil analysis must not be cached")
	}
}
