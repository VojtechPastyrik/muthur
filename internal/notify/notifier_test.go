package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Each test constructs the notifier struct directly (same package) so we can
// inject a test HTTP client. The factory functions are tested separately in
// receiver_test.go.

func TestDiscord_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected application/json content type")
		}
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		json.Unmarshal(body, &payload)
		if payload["content"] == "" {
			t.Error("content should not be empty")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	d := &Discord{name: "test-discord", webhookURL: server.URL, client: server.Client()}
	msg := &Message{Text: "test alert"}

	if err := d.Send(context.Background(), msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Name() != "test-discord" {
		t.Errorf("expected name test-discord, got %s", d.Name())
	}
}

func TestSlack_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		json.Unmarshal(body, &payload)
		if payload["text"] == "" {
			t.Error("text should not be empty")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	s := &Slack{name: "test-slack", webhookURL: server.URL, client: server.Client()}
	msg := &Message{Text: "test alert"}

	if err := s.Send(context.Background(), msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPagerDuty_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		json.Unmarshal(body, &payload)
		if payload["routing_key"] != "test-key" {
			t.Errorf("expected routing_key test-key, got %v", payload["routing_key"])
		}
		if payload["event_action"] != "trigger" {
			t.Errorf("expected event_action trigger, got %v", payload["event_action"])
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	pd := &PagerDuty{
		name:       "test-pd",
		routingKey: "test-key",
		url:        server.URL,
		client:     server.Client(),
	}
	msg := &Message{Text: "test alert", Severity: "critical", ClusterID: "cluster-a", AlertName: "test", Namespace: "default"}

	if err := pd.Send(context.Background(), msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWebhook_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected application/json content type")
		}
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		json.Unmarshal(body, &payload)
		if payload["text"] == "" {
			t.Error("text should not be empty")
		}
		if payload["cluster_id"] != "cluster-a" {
			t.Errorf("expected cluster_id cluster-a, got %v", payload["cluster_id"])
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	wh := &Webhook{name: "test-webhook", url: server.URL, client: server.Client()}
	msg := &Message{
		Text:      "test alert",
		ClusterID: "cluster-a",
		AlertName: "HighMem",
		Namespace: "default",
	}

	if err := wh.Send(context.Background(), msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWebhook_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	wh := &Webhook{name: "test", url: server.URL, client: server.Client()}
	msg := &Message{Text: "test"}

	if err := wh.Send(context.Background(), msg); err == nil {
		t.Error("expected error on 500 response")
	}
}
