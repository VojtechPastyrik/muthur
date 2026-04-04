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

	pb "github.com/VojtechPastyrik/muthur-central/proto"
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

	c := NewClient(server.URL, 2*time.Hour, true, zap.NewNop())
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
	c := NewClient("http://localhost", 2*time.Hour, false, zap.NewNop())

	err := c.CreateSilence(context.Background(), &pb.AlertPayload{}, "test")
	if err != nil {
		t.Fatalf("disabled client should return nil, got: %v", err)
	}
}
