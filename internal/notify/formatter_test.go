package notify

import (
	"strings"
	"testing"

	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

func TestFormatMessage_FullPayload(t *testing.T) {
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

	checks := []string{
		"[CRITICAL]",
		"cluster-a",
		"HighMemory",
		"pod / app-123",
		"Node:     node-01",
		"Restarts: 3",
		"OOM killer terminated the pod",
		"Memory usage reached 128Mi limit",
		"Increase memory limit to 256Mi",
		"grafana.example.com",
	}

	for _, check := range checks {
		if !strings.Contains(msg.Text, check) {
			t.Errorf("message missing: %q", check)
		}
	}
}

func TestFormatMessage_NoEmoji(t *testing.T) {
	payload := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "Test",
		Severity:  "warning",
	}
	analysis := &evaluator.Analysis{
		RootCause: "test",
		Evidence:  "test",
		Action:    "test",
	}

	msg := FormatMessage(payload, analysis, "")

	emojis := []string{"🔴", "🟡", "🟢", "⚠️", "❌", "✅", "🚨", "💀"}
	for _, e := range emojis {
		if strings.Contains(msg.Text, e) {
			t.Errorf("message should not contain emoji: %s", e)
		}
	}
}

func TestFormatMessage_NilAnalysis(t *testing.T) {
	payload := &pb.AlertPayload{
		ClusterId: "cluster-a",
		AlertName: "Test",
		Severity:  "info",
	}

	msg := FormatMessage(payload, nil, "")

	if !strings.Contains(msg.Text, "[INFO]") {
		t.Error("message should contain severity")
	}
	if strings.Contains(msg.Text, "Root cause") {
		t.Error("should not have root cause with nil analysis")
	}
}
