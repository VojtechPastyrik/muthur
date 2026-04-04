package evaluator

import (
	"strings"
	"testing"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

func TestBuildPrompt_ContainsAllFields(t *testing.T) {
	payload := &pb.AlertPayload{
		ClusterId:   "cluster-a",
		AlertName:   "HighMemory",
		Severity:    "critical",
		Namespace:   "default",
		PodName:     "app-123",
		FiredAt:     1700000000,
		Summary:     "Memory exceeded limit",
		Description: "Pod is using too much memory",
		Target: &pb.AlertTarget{
			TargetType:   "pod",
			PodName:      "app-123",
			Node:         "node-01",
			ResolvedPods: []string{"app-123"},
		},
		RedactedLogs: []string{
			"2024-01-01 OOM killer terminated process",
			"2024-01-01 container killed, email=[email]",
		},
		Metrics: []*pb.MetricSeries{
			{
				MetricName:  "container_memory_working_set_bytes",
				Description: "Working set memory",
				Unit:        "bytes",
				Points: []*pb.DataPoint{
					{Timestamp: 1700000000, Value: 134217728},
				},
			},
		},
		PodMetas: []*pb.PodMeta{
			{
				PodName:       "app-123",
				MemoryLimit:   "128Mi",
				MemoryRequest: "64Mi",
				CpuLimit:      "500m",
				CpuRequest:    "100m",
				NodeName:      "node-01",
				RestartCount:  3,
				Phase:         "Running",
			},
		},
		Labels: []*pb.Label{
			{Name: "app", Value: "my-app"},
		},
		TotalLogLines:    100,
		RedactedLogLines: 2,
		TotalReplacements: 3,
	}

	prompt := buildPrompt(payload)

	checks := []string{
		"cluster-a",
		"HighMemory",
		"critical",
		"default",
		"pod",
		"app-123",
		"node-01",
		"OOM killer",
		"container_memory_working_set_bytes",
		"128Mi",
		"Restarts: 3",
		"app=my-app",
		"100 total lines",
		"Return only JSON",
	}

	for _, check := range checks {
		if !strings.Contains(prompt, check) {
			t.Errorf("prompt missing: %q", check)
		}
	}
}

func TestBuildPrompt_EmptyPayload(t *testing.T) {
	payload := &pb.AlertPayload{}
	prompt := buildPrompt(payload)

	if !strings.Contains(prompt, "Return only JSON") {
		t.Error("prompt should always contain JSON instructions")
	}
}
