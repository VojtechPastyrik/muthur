package ingest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	pb "github.com/VojtechPastyrik/muthur-central/proto"
)

type mockProcessor struct {
	received []*pb.AlertPayload
}

func (m *mockProcessor) Process(payload *pb.AlertPayload) {
	m.received = append(m.received, payload)
}

func TestHandler_ValidRequest(t *testing.T) {
	proc := &mockProcessor{}
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
	if len(proc.received) != 1 {
		t.Fatalf("expected 1 processed payload, got %d", len(proc.received))
	}
	if proc.received[0].AlertName != "HighMemory" {
		t.Errorf("expected alert HighMemory, got %s", proc.received[0].AlertName)
	}
}

func TestHandler_MissingToken(t *testing.T) {
	handler := NewHandler(map[string]string{}, &mockProcessor{}, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandler_WrongToken(t *testing.T) {
	tokenMap := map[string]string{"cluster-a": "correct-token"}
	handler := NewHandler(tokenMap, &mockProcessor{}, zap.NewNop())

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
	handler := NewHandler(tokenMap, &mockProcessor{}, zap.NewNop())

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
	handler := NewHandler(map[string]string{}, &mockProcessor{}, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/ingest", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandler_InvalidProtobuf(t *testing.T) {
	tokenMap := map[string]string{"cluster-a": "token-a"}
	handler := NewHandler(tokenMap, &mockProcessor{}, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader([]byte("not protobuf")))
	req.Header.Set("X-Collector-Token", "token-a")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
