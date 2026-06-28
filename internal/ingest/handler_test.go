package ingest

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	"github.com/VojtechPastyrik/muthur/internal/store"
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

// newHandler wires the handler with an in-memory store-backed replay guard.
// Tests that need to share state across calls (e.g. nonce reuse) should reuse
// the returned handler.
func newHandler(t *testing.T) (*Handler, *mockProcessor) {
	t.Helper()
	proc := newMockProcessor()
	guard := auth.NewReplayGuard(store.NewMemory(), 5*time.Minute, "muthur:")
	return NewHandler(guard, proc, zap.NewNop()), proc
}

// freshNonce returns a 32-hex-char random nonce. Each test call gets a unique
// one, so cross-call replay collisions only happen when a test deliberately
// reuses the same string.
func freshNonce(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// newAuthedRequest builds an /ingest POST with an Identity bound to ctx, valid
// replay headers, and the given payload. nonce is overridable so reuse tests
// can pin it.
func newAuthedRequest(t *testing.T, id *auth.Identity, payload *pb.AlertPayload, nonce string) *http.Request {
	t.Helper()
	body, err := proto.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(body))
	r.Header.Set(auth.HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
	r.Header.Set(auth.HeaderNonce, nonce)
	return r.WithContext(auth.WithContext(r.Context(), id))
}

func TestHandler_ValidRequest(t *testing.T) {
	handler, proc := newHandler(t)
	id := &auth.Identity{ClusterID: "cluster-a"}
	payload := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "HighMemory",
		Severity:  "critical",
		Namespace: "default",
	}
	req := newAuthedRequest(t, id, payload, freshNonce(t))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
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

func TestHandler_MissingIdentity(t *testing.T) {
	// No Identity in context simulates the route being mounted outside the
	// auth middleware. Must fail closed.
	handler, _ := newHandler(t)
	payload := &pb.AlertPayload{ClusterId: "cluster-a"}
	body, _ := proto.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(body))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHandler_ClusterIDMismatch(t *testing.T) {
	// Cert says cluster-a, payload claims cluster-b. Must be forbidden so a
	// compromised collector cannot ship data labelled as another tenant.
	handler, proc := newHandler(t)
	id := &auth.Identity{ClusterID: "cluster-a"}
	payload := &pb.AlertPayload{ClusterId: "cluster-b", AlertName: "spoof"}
	req := newAuthedRequest(t, id, payload, freshNonce(t))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	select {
	case got := <-proc.received:
		t.Errorf("processor saw payload despite cluster mismatch: %v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	handler, _ := newHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/ingest", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandler_InvalidProtobuf(t *testing.T) {
	handler, _ := newHandler(t)
	id := &auth.Identity{ClusterID: "cluster-a"}
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader([]byte("not protobuf")))
	req.Header.Set(auth.HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set(auth.HeaderNonce, freshNonce(t))
	req = req.WithContext(auth.WithContext(req.Context(), id))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandler_ReplayedNonce(t *testing.T) {
	handler, proc := newHandler(t)
	id := &auth.Identity{ClusterID: "cluster-a"}
	payload := &pb.AlertPayload{ClusterId: "cluster-a", AlertName: "x"}
	nonce := freshNonce(t)

	// First request burns the nonce.
	first := newAuthedRequest(t, id, payload, nonce)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, first)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("first call status = %d, want 202", rr.Code)
	}
	<-proc.received

	// Replayed call with same nonce must be rejected.
	second := newAuthedRequest(t, id, payload, nonce)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, second)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("replay status = %d, want 401", rr2.Code)
	}
}

func TestHandler_MissingReplayHeaders(t *testing.T) {
	handler, _ := newHandler(t)
	id := &auth.Identity{ClusterID: "cluster-a"}
	payload := &pb.AlertPayload{ClusterId: "cluster-a"}
	body, _ := proto.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewReader(body))
	req = req.WithContext(auth.WithContext(req.Context(), id))
	// No replay headers set.

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
