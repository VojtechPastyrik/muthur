package dedup

import (
	"testing"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur-central/proto"
)

func TestDedup_FirstAlert(t *testing.T) {
	d := New(15, zap.NewNop())

	payload := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "HighMemory",
		Namespace: "default",
		PodName:   "app-123",
	}

	if d.IsDuplicate(payload) {
		t.Error("first alert should not be duplicate")
	}
}

func TestDedup_DuplicateAlert(t *testing.T) {
	d := New(15, zap.NewNop())

	payload := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "HighMemory",
		Namespace: "default",
		PodName:   "app-123",
	}

	d.IsDuplicate(payload) // first call
	if !d.IsDuplicate(payload) {
		t.Error("second identical alert should be duplicate")
	}
}

func TestDedup_DifferentAlerts(t *testing.T) {
	d := New(15, zap.NewNop())

	p1 := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "HighMemory",
		Namespace: "default",
		PodName:   "app-123",
	}
	p2 := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "HighCPU",
		Namespace: "default",
		PodName:   "app-123",
	}

	d.IsDuplicate(p1)
	if d.IsDuplicate(p2) {
		t.Error("different alert name should not be duplicate")
	}
}

func TestDedup_DifferentClusters(t *testing.T) {
	d := New(15, zap.NewNop())

	p1 := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "HighMemory",
		Namespace: "default",
	}
	p2 := &pb.AlertPayload{
		ClusterId: "cluster-b",
		AlertName: "HighMemory",
		Namespace: "default",
	}

	d.IsDuplicate(p1)
	if d.IsDuplicate(p2) {
		t.Error("same alert from different cluster should not be duplicate")
	}
}
