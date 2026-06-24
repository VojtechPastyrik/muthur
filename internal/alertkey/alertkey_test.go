package alertkey

import (
	"testing"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

func TestID_DeterministicAndShaped(t *testing.T) {
	p := &pb.AlertPayload{ClusterId: "c1", AlertName: "OOM", Namespace: "ns", PodName: "pod-1", FiredAt: 1000}
	a := ID(p)
	b := ID(p)
	if a != b {
		t.Fatalf("ID not deterministic: %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("ID len = %d, want 16", len(a))
	}
}

func TestID_DiffersOnIdentityFields(t *testing.T) {
	base := &pb.AlertPayload{ClusterId: "c1", AlertName: "OOM", Namespace: "ns", PodName: "pod-1", FiredAt: 1000}
	other := &pb.AlertPayload{ClusterId: "c1", AlertName: "OOM", Namespace: "ns", PodName: "pod-2", FiredAt: 1000}
	if ID(base) == ID(other) {
		t.Error("different pod should yield different ID")
	}
}
