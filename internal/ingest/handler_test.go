package ingest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

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

func TestHandler_ValidRequest(t *testing.T) {
	proc := newMockProcessor()
	tokenMap := map[string]string{"cluster-a": "token-a"}
	handler := NewHandler(tokenMap, proc, zap.NewNop())

	payload := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "HighMemory",
		Severity:  "critical",
		Namespace: "default",
	}
	body, _ := proto.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(body))
	req.Header.Set("X-Collector-Token", "token-a")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
	// Process runs in a goroutine — wait for the payload to arrive on the
	// channel instead of racing on a slice.
	select {
	case got := <-proc.received:
		if got.AlertName != "HighMemory" {
			t.Errorf("expected alert HighMemory, got %s", got.AlertName)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for async Process")
	}
}

func TestHandler_MissingToken(t *testing.T) {
	handler := NewHandler(map[string]string{}, newMockProcessor(), zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandler_WrongToken(t *testing.T) {
	tokenMap := map[string]string{"cluster-a": "correct-token"}
	handler := NewHandler(tokenMap, newMockProcessor(), zap.NewNop())

	payload := &pb.AlertPayload{ClusterId: "cluster-a"}
	body, _ := proto.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(body))
	req.Header.Set("X-Collector-Token", "wrong-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandler_UnknownCluster(t *testing.T) {
	tokenMap := map[string]string{"cluster-a": "token-a"}
	handler := NewHandler(tokenMap, newMockProcessor(), zap.NewNop())

	payload := &pb.AlertPayload{ClusterId: "cluster-unknown"}
	body, _ := proto.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(body))
	req.Header.Set("X-Collector-Token", "token-a")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	handler := NewHandler(map[string]string{}, newMockProcessor(), zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/ingest", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandler_InvalidProtobuf(t *testing.T) {
	tokenMap := map[string]string{"cluster-a": "token-a"}
	handler := NewHandler(tokenMap, newMockProcessor(), zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader([]byte("not protobuf")))
	req.Header.Set("X-Collector-Token", "token-a")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
