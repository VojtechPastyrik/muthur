package ingest

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

type mockProcessor struct {
	received chan *pb.AlertPayload
}

func newMockProcessor() *mockProcessor {
	return &mockProcessor{received: make(chan *pb.AlertPayload, 4)}
}

func (m *mockProcessor) Process(payload *pb.AlertPayload) {
	m.received <- payload
}

func newHandler(t *testing.T) (*Handler, *mockProcessor) {
	t.Helper()
	proc := newMockProcessor()
	return NewHandler(proc, zap.NewNop()), proc
}

func TestIngest_ValidRequest(t *testing.T) {
	handler, proc := newHandler(t)
	id := &auth.Identity{ClusterID: "cluster-a"}
	ctx := auth.WithContext(context.Background(), id)
	payload := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "HighMemory",
		Severity:  "critical",
		Namespace: "default",
	}

	if err := handler.Ingest(ctx, payload); err != nil {
		t.Fatalf("Ingest err: %v", err)
	}
	select {
	case got := <-proc.received:
		if got.AlertName != "HighMemory" {
			t.Errorf("alert = %s, want HighMemory", got.AlertName)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for async Process")
	}
}

func TestIngest_MissingIdentity(t *testing.T) {
	// No Identity in context simulates the RPC reaching the handler outside
	// the auth interceptor. Must fail closed.
	handler, _ := newHandler(t)
	err := handler.Ingest(context.Background(), &pb.AlertPayload{ClusterId: "cluster-a"})
	if !errors.Is(err, ErrIngestNoIdentity) {
		t.Errorf("err = %v, want ErrIngestNoIdentity", err)
	}
}

func TestIngest_ClusterIDMismatch(t *testing.T) {
	// Cert says cluster-a, payload claims cluster-b. Must be forbidden so a
	// compromised collector cannot ship data labelled as another tenant.
	handler, proc := newHandler(t)
	id := &auth.Identity{ClusterID: "cluster-a"}
	ctx := auth.WithContext(context.Background(), id)
	payload := &pb.AlertPayload{ClusterId: "cluster-b", AlertName: "spoof"}

	if err := handler.Ingest(ctx, payload); !errors.Is(err, ErrIngestForbidden) {
		t.Errorf("err = %v, want ErrIngestForbidden", err)
	}
	select {
	case got := <-proc.received:
		t.Errorf("processor saw payload despite cluster mismatch: %v", got)
	case <-time.After(50 * time.Millisecond):
	}
}
