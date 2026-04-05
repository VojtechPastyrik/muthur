package notify

import (
	"strings"
	"testing"

	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

func TestFormatMessage_StructuredFields(t *testing.T) {
	payload := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "HighMemory",
		Severity:  "critical",
		Namespace: "default",
		PodName:   "app-123",
		Target: &pb.AlertTarget{
			TargetType: "pod",
			PodName:    "app-123",
			Node:       "node-01",
		},
		PodMetas: []*pb.PodMeta{
			{
				PodName:       "app-123",
				RestartCount:  3,
				MemoryLimit:   "128Mi",
				MemoryRequest: "64Mi",
			},
		},
	}

	analysis := &evaluator.Analysis{
		Severity:  "critical",
		RootCause: "OOM killer terminated the pod",
		Evidence:  "Memory usage reached 128Mi limit",
		Action:    "Increase memory limit to 256Mi",
	}

	msg := FormatMessage(payload, analysis, "https://grafana.example.com")

	if msg.Payload != payload {
		t.Error("Payload not preserved in Message")
	}
	if msg.Analysis != analysis {
		t.Error("Analysis not preserved in Message")
	}
	if !strings.Contains(msg.GrafanaURL, "grafana.example.com") {
		t.Errorf("expected grafana URL, got %q", msg.GrafanaURL)
	}
	if !strings.Contains(msg.GrafanaURL, "app-123") {
		t.Errorf("expected pod name in grafana URL, got %q", msg.GrafanaURL)
	}
	if msg.Severity() != "critical" {
		t.Errorf("expected critical severity, got %q", msg.Severity())
	}
	if msg.Title() != "[CRITICAL] cluster-a / HighMemory" {
		t.Errorf("unexpected title: %q", msg.Title())
	}
	if msg.Resolved() {
		t.Error("message should not be marked resolved")
	}
	if tl := targetLine(payload); tl != "pod / app-123" {
		t.Errorf("unexpected target line: %q", tl)
	}
	if r := restartInfo(payload); r != "3 restarts" {
		t.Errorf("unexpected restart info: %q", r)
	}
}

func TestFormatMessage_Resolved(t *testing.T) {
	payload := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "HighMemory",
		Severity:  "critical",
		Status:    "resolved",
	}
	msg := FormatMessage(payload, nil, "")
	if !msg.Resolved() {
		t.Error("expected Resolved() == true")
	}
	if msg.Title() != "[RESOLVED] cluster-a / HighMemory" {
		t.Errorf("unexpected resolved title: %q", msg.Title())
	}
}

func TestFormatMessage_NilAnalysisNoGrafanaURL(t *testing.T) {
	payload := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "Test",
		Severity:  "info",
	}

	msg := FormatMessage(payload, nil, "")
	if msg.Analysis != nil {
		t.Error("Analysis should be nil")
	}
	if msg.GrafanaURL != "" {
		t.Errorf("GrafanaURL should be empty without base URL, got %q", msg.GrafanaURL)
	}
	if msg.Severity() != "info" {
		t.Errorf("expected info severity, got %q", msg.Severity())
	}
}
