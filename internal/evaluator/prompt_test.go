package evaluator

import (
	"strings"
	"testing"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

func samplePayload() *pb.AlertPayload {
	return &pb.AlertPayload{
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
				Points:      []*pb.DataPoint{{Timestamp: 1700000000, Value: 134217728}},
			},
		},
		PodMetas: []*pb.PodMeta{
			{
				PodName: "app-123", MemoryLimit: "128Mi", MemoryRequest: "64Mi",
				CpuLimit: "500m", CpuRequest: "100m", NodeName: "node-01",
				RestartCount: 3, Phase: "Running",
			},
		},
		Labels:            []*pb.Label{{Name: "app", Value: "my-app"}},
		TotalLogLines:     100,
		RedactedLogLines:  2,
		TotalReplacements: 3,
	}
}

func TestBuildPrompt_ContainsAllFields(t *testing.T) {
	prompt := buildPrompt(samplePayload(), nil)

	checks := []string{
		"cluster-a", "HighMemory", "critical", "default", "pod", "app-123",
		"node-01", "OOM killer", "container_memory_working_set_bytes", "128Mi",
		"Restarts: 3", "app=my-app", "100 total lines", "report_analysis",
	}
	for _, check := range checks {
		if !strings.Contains(prompt.String(),check) {
			t.Errorf("prompt missing: %q", check)
		}
	}
}

func TestBuildPrompt_EmptyPayload(t *testing.T) {
	prompt := buildPrompt(&pb.AlertPayload{}, nil)
	if !strings.Contains(prompt.String(),"report_analysis") {
		t.Error("prompt should always instruct calling report_analysis")
	}
}

func TestBuildPrompt_FewShot(t *testing.T) {
	examples := []Example{
		{AlertName: "HighMemory", Verdict: "wrong", Analysis: &Analysis{RootCause: "network blip"}},
		{AlertName: "HighMemory", Verdict: "useful", Analysis: &Analysis{RootCause: "memory leak"}},
	}
	prompt := buildPrompt(samplePayload(), examples)
	if !strings.Contains(prompt.String(),"WRONG") || !strings.Contains(prompt.String(),"network blip") {
		t.Error("prompt missing wrong-verdict few-shot")
	}
	if !strings.Contains(prompt.String(),"memory leak") {
		t.Error("prompt missing useful-verdict few-shot")
	}
}

func TestBuildIncidentPrompt(t *testing.T) {
	a := samplePayload()
	b := samplePayload()
	b.AlertName = "PodCrashLoop"
	prompt := buildIncidentPrompt([]*pb.AlertPayload{a, b}, nil)
	if !strings.Contains(prompt.String(),"2 correlated alerts") {
		t.Error("incident prompt should state the alert count")
	}
	if !strings.Contains(prompt.String(),"HighMemory") || !strings.Contains(prompt.String(),"PodCrashLoop") {
		t.Error("incident prompt should render all alerts")
	}
}

func TestSignature_StableAcrossPods(t *testing.T) {
	a := samplePayload()
	b := samplePayload()
	b.PodName = "app-999"
	b.Target.PodName = "app-999"
	if Signature(a) != Signature(b) {
		t.Errorf("signature should ignore pod name:\n a=%q\n b=%q", Signature(a), Signature(b))
	}
}
