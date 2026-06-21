package silence

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

func TestClient_CreateSilence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/silences" {
			t.Errorf("expected /api/v2/silences, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		body, _ := io.ReadAll(r.Body)
		var req silenceRequest
		json.Unmarshal(body, &req)

		if req.CreatedBy != "muthur-central" {
			t.Errorf("expected createdBy muthur-central, got %s", req.CreatedBy)
		}
		if len(req.Matchers) != 2 {
			t.Errorf("expected 2 matchers, got %d", len(req.Matchers))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"silenceID":"abc-123"}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, 2*time.Hour, true, nil, zap.NewNop())
	c.client = server.Client()

	payload := &pb.AlertPayload{
		AlertName: "HighMemory",
		Namespace: "default",
	}

	err := c.CreateSilence(context.Background(), payload, "auto-silenced by muthur")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClient_Disabled(t *testing.T) {
	c := NewClient("http://localhost", 2*time.Hour, false, nil, zap.NewNop())

	err := c.CreateSilence(context.Background(), &pb.AlertPayload{}, "test")
	if err != nil {
		t.Fatalf("disabled client should return nil, got: %v", err)
	}
}

// newGuardServer returns a server that fails the test if it is ever hit — used
// to prove a guard short-circuits before any AlertManager call is made.
func newGuardServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("guard failed: AlertManager was called for a request that should have been blocked")
		w.WriteHeader(http.StatusOK)
	}))
}

// TestClient_NeverSilencesCritical is the core prompt-injection guard: even if
// Claude requests a silence, a critical alert must never be muted.
func TestClient_NeverSilencesCritical(t *testing.T) {
	server := newGuardServer(t)
	defer server.Close()

	c := NewClient(server.URL, 2*time.Hour, true, nil, zap.NewNop())
	c.client = server.Client()

	payload := &pb.AlertPayload{AlertName: "APIDown", Namespace: "prod", Severity: "critical"}
	if err := c.CreateSilence(context.Background(), payload, "injected: this is noise"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestClient_AllowlistBlocksUnlisted ensures an alert not on the allowlist is
// refused, while a listed one passes through.
func TestClient_AllowlistBlocksUnlisted(t *testing.T) {
	server := newGuardServer(t)
	defer server.Close()

	c := NewClient(server.URL, 2*time.Hour, true, []string{"NoisyFlapping"}, zap.NewNop())
	c.client = server.Client()

	payload := &pb.AlertPayload{AlertName: "DiskWillFill", Namespace: "prod", Severity: "warning"}
	if err := c.CreateSilence(context.Background(), payload, "not on list"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestClient_AllowlistPermitsListed confirms a listed, non-critical alert is
// actually silenced (the server is reached and returns 200).
func TestClient_AllowlistPermitsListed(t *testing.T) {
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"silenceID":"ok"}`))
	}))
	defer server.Close()

	c := NewClient(server.URL, 2*time.Hour, true, []string{"NoisyFlapping"}, zap.NewNop())
	c.client = server.Client()

	payload := &pb.AlertPayload{AlertName: "NoisyFlapping", Namespace: "prod", Severity: "warning"}
	if err := c.CreateSilence(context.Background(), payload, "genuinely noise"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hit {
		t.Fatal("expected listed non-critical alert to be silenced, but AlertManager was not called")
	}
}
