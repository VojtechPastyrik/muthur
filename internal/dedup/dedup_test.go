package dedup

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

func newDedup() *Deduplicator {
	return New(15, store.NewMemory(), zap.NewNop())
}

func TestDedup_FirstAlert(t *testing.T) {
	d := newDedup()
	payload := &pb.AlertPayload{ClusterId: "cluster-a", AlertName: "HighMemory", Namespace: "default", PodName: "app-123"}
	if d.IsDuplicate(context.Background(), payload) {
		t.Error("first alert should not be duplicate")
	}
}

func TestDedup_DuplicateAlert(t *testing.T) {
	d := newDedup()
	payload := &pb.AlertPayload{ClusterId: "cluster-a", AlertName: "HighMemory", Namespace: "default", PodName: "app-123"}
	d.IsDuplicate(context.Background(), payload)
	if !d.IsDuplicate(context.Background(), payload) {
		t.Error("second identical alert should be duplicate")
	}
}

func TestDedup_DifferentAlerts(t *testing.T) {
	d := newDedup()
	p1 := &pb.AlertPayload{ClusterId: "cluster-a", AlertName: "HighMemory", Namespace: "default", PodName: "app-123"}
	p2 := &pb.AlertPayload{ClusterId: "cluster-a", AlertName: "HighCPU", Namespace: "default", PodName: "app-123"}
	d.IsDuplicate(context.Background(), p1)
	if d.IsDuplicate(context.Background(), p2) {
		t.Error("different alert name should not be duplicate")
	}
}

func TestDedup_DifferentClusters(t *testing.T) {
	d := newDedup()
	p1 := &pb.AlertPayload{ClusterId: "cluster-a", AlertName: "HighMemory", Namespace: "default"}
	p2 := &pb.AlertPayload{ClusterId: "cluster-b", AlertName: "HighMemory", Namespace: "default"}
	d.IsDuplicate(context.Background(), p1)
	if d.IsDuplicate(context.Background(), p2) {
		t.Error("same alert from different cluster should not be duplicate")
	}
}
