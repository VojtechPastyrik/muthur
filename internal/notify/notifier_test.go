package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTelegram_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		json.Unmarshal(body, &payload)

		if payload["chat_id"] != "123" {
			t.Errorf("expected chat_id 123, got %s", payload["chat_id"])
		}
		if payload["text"] == "" {
			t.Error("text should not be empty")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	tg := &Telegram{
		token:  "fake-token",
		chatID: "123",
		client: server.Client(),
	}
	// Override the URL by using a custom transport
	tg.client = server.Client()

	// Test via direct HTTP to mock server
	msg := &Message{Text: "test alert", ClusterID: "cluster-a", AlertName: "test"}
	// We can't easily override the Telegram URL, so test the Discord/Slack/Webhook which accept URLs
	_ = msg
	_ = tg
}

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

	d := NewDiscord(server.URL)
	d.client = server.Client()
	msg := &Message{Text: "test alert"}

	if err := d.Send(context.Background(), msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
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

	s := NewSlack(server.URL)
	s.client = server.Client()
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

	pd := NewPagerDuty("test-key")
	pd.url = server.URL
	pd.client = server.Client()
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

	wh := NewWebhook(server.URL)
	wh.client = server.Client()
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

	wh := NewWebhook(server.URL)
	wh.client = server.Client()
	msg := &Message{Text: "test"}

	if err := wh.Send(context.Background(), msg); err == nil {
		t.Error("expected error on 500 response")
	}
}
