package incident

import (
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

func TestCorrelator_GroupsSameNamespace(t *testing.T) {
	var mu sync.Mutex
	var groups [][]*pb.AlertPayload
	done := make(chan struct{})

	c := New(true, 0, 25, func(alerts []*pb.AlertPayload) {
		mu.Lock()
		groups = append(groups, alerts)
		mu.Unlock()
		close(done)
	}, zap.NewNop())
	// Override window to a short, test-friendly duration.
	c.window = 30 * time.Millisecond

	c.Add(&pb.AlertPayload{ClusterId: "a", AlertName: "HighMemory", Namespace: "default"})
	c.Add(&pb.AlertPayload{ClusterId: "a", AlertName: "PodCrash", Namespace: "default"})
	c.Add(&pb.AlertPayload{ClusterId: "a", AlertName: "OOM", Namespace: "default"})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("flush never fired")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(groups) != 1 || len(groups[0]) != 3 {
		t.Fatalf("expected one group of 3, got %d groups", len(groups))
	}
}

func TestCorrelator_SeparateNamespaces(t *testing.T) {
	var mu sync.Mutex
	count := 0
	c := New(true, 0, 25, func(alerts []*pb.AlertPayload) {
		mu.Lock()
		count++
		mu.Unlock()
	}, zap.NewNop())
	c.window = 20 * time.Millisecond

	c.Add(&pb.AlertPayload{ClusterId: "a", AlertName: "X", Namespace: "ns1"})
	c.Add(&pb.AlertPayload{ClusterId: "a", AlertName: "Y", Namespace: "ns2"})

	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if count != 2 {
		t.Fatalf("expected 2 separate incidents, got %d", count)
	}
}

func TestRepresentative_PicksHighestSeverity(t *testing.T) {
	alerts := []*pb.AlertPayload{
		{AlertName: "a", Severity: "info"},
		{AlertName: "b", Severity: "critical"},
		{AlertName: "c", Severity: "warning"},
	}
	rep := Representative(alerts)
	if rep.AlertName != "b" {
		t.Fatalf("representative = %s, want b (critical)", rep.AlertName)
	}
}

func TestGroupKey_NodeOverNamespace(t *testing.T) {
	p := &pb.AlertPayload{ClusterId: "a", Namespace: "default", Target: &pb.AlertTarget{Node: "node-1"}}
	if got := groupKey(p); got != "a|node|node-1" {
		t.Fatalf("groupKey = %q, want node scope", got)
	}
}
