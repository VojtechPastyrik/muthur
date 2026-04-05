package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// Each test constructs the notifier struct directly (same package) so we can
// inject a test HTTP client. The factory functions are tested separately in
// receiver_test.go.

func sampleMessage(resolved bool) *Message {
	status := "firing"
	if resolved {
		status = "resolved"
	}
	return &Message{
		Payload: &pb.AlertPayload{
			ClusterId: "cluster-a",
			AlertName: "HighMemory",
			Severity:  "critical",
			Namespace: "default",
			PodName:   "app-123",
			Summary:   "Pod memory pressure",
			Status:    status,
			FiredAt:   1712345678,
			Target:    &pb.AlertTarget{TargetType: "pod", PodName: "app-123"},
		},
		Analysis: &evaluator.Analysis{
			RootCause: "container exceeded limit",
			Evidence:  "memory usage 128Mi == limit",
			Action:    "raise limit to 256Mi",
		},
		GrafanaURL: "https://grafana.example.com/explore?x=1",
	}
}

func TestDiscord_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected application/json content type")
		}
		body, _ := io.ReadAll(r.Body)
		var payload discordPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("invalid JSON body: %v", err)
		}
		if len(payload.Embeds) != 1 {
			t.Fatalf("expected 1 embed, got %d", len(payload.Embeds))
		}
		e := payload.Embeds[0]
		if !strings.Contains(e.Title, "cluster-a") || !strings.Contains(e.Title, "HighMemory") {
			t.Errorf("title missing cluster/alert: %q", e.Title)
		}
		if e.Color != colorCritical {
			t.Errorf("expected critical color, got %d", e.Color)
		}
		if e.URL == "" {
			t.Error("expected Grafana URL on embed")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	d := &Discord{name: "test-discord", webhookURL: server.URL, client: server.Client()}
	if err := d.Send(context.Background(), sampleMessage(false)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Name() != "test-discord" {
		t.Errorf("expected name test-discord, got %s", d.Name())
	}
}

func TestDiscord_ResolvedColor(t *testing.T) {
	var got discordEmbed
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload discordPayload
		json.NewDecoder(r.Body).Decode(&payload)
		got = payload.Embeds[0]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	d := &Discord{name: "d", webhookURL: server.URL, client: server.Client()}
	if err := d.Send(context.Background(), sampleMessage(true)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Color != colorResolved {
		t.Errorf("expected resolved color, got %d", got.Color)
	}
	if !strings.Contains(got.Title, "RESOLVED") {
		t.Errorf("resolved title should start with [RESOLVED], got %q", got.Title)
	}
}

func TestSlack_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload slackPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("invalid JSON body: %v", err)
		}
		if len(payload.Attachments) != 1 {
			t.Fatalf("expected 1 attachment")
		}
		if payload.Attachments[0].Color != slackColorCritical {
			t.Errorf("expected critical color, got %q", payload.Attachments[0].Color)
		}
		if len(payload.Attachments[0].Blocks) == 0 {
			t.Error("expected blocks")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	s := &Slack{name: "test-slack", webhookURL: server.URL, client: server.Client()}
	if err := s.Send(context.Background(), sampleMessage(false)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTelegram_HTMLParseMode(t *testing.T) {
	var got telegramSendMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Override the Telegram HTTP URL by sending to server.URL directly; we do
	// that by hand-building a Telegram with a custom sendMessage path hack is
	// not trivial — instead exercise the builder.
	_ = server
	msg := sampleMessage(false)
	html := buildTelegramHTML(msg)
	if !strings.Contains(html, "<b>") {
		t.Error("telegram HTML should contain bold tags")
	}
	if !strings.Contains(html, "cluster-a") {
		t.Error("missing cluster in html")
	}
	if !strings.Contains(html, "Root cause") {
		t.Error("missing root cause heading")
	}
	// Escape check — insert a dangerous string via summary
	msg.Payload.Summary = "a<b>&c"
	msg.Analysis = nil
	html = buildTelegramHTML(msg)
	if strings.Contains(html, "a<b>&c") {
		t.Error("html should escape angle brackets and ampersand in summary")
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
		pl, _ := payload["payload"].(map[string]any)
		if pl == nil || pl["severity"] != "critical" {
			t.Errorf("expected critical severity in payload, got %v", pl)
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
	if err := pd.Send(context.Background(), sampleMessage(false)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPagerDuty_Resolve(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		if payload["event_action"] != "resolve" {
			t.Errorf("expected event_action=resolve, got %v", payload["event_action"])
		}
		if _, ok := payload["payload"]; ok {
			t.Error("resolve events must not contain payload object")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	pd := &PagerDuty{name: "pd", routingKey: "k", url: server.URL, client: server.Client()}
	if err := pd.Send(context.Background(), sampleMessage(true)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWebhook_Send(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected application/json content type")
		}
		var payload webhookPayload
		json.NewDecoder(r.Body).Decode(&payload)
		if payload.ClusterID != "cluster-a" {
			t.Errorf("expected cluster_id cluster-a, got %q", payload.ClusterID)
		}
		if payload.AlertName != "HighMemory" {
			t.Errorf("expected alert HighMemory, got %q", payload.AlertName)
		}
		if payload.Analysis == nil || payload.Analysis.RootCause == "" {
			t.Error("expected analysis in webhook payload")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	wh := &Webhook{name: "test-webhook", url: server.URL, client: server.Client()}
	if err := wh.Send(context.Background(), sampleMessage(false)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWebhook_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	wh := &Webhook{name: "test", url: server.URL, client: server.Client()}
	if err := wh.Send(context.Background(), sampleMessage(false)); err == nil {
		t.Error("expected error on 500 response")
	}
}
