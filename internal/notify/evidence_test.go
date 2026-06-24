package notify

import (
	"strings"
	"testing"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

func TestAttachEvidence_TailAndCap(t *testing.T) {
	logs := []string{"l1", "l2", "l3", "l4", "l5"}
	p := &pb.AlertPayload{RedactedLogs: logs}
	msg := &Message{Payload: p}

	AttachEvidence(msg, p, EvidenceConfig{Enabled: true, LogLines: 3})

	if len(msg.EvidenceLogs) != 3 {
		t.Fatalf("want 3 tail lines, got %d (%v)", len(msg.EvidenceLogs), msg.EvidenceLogs)
	}
	if msg.EvidenceLogs[0] != "l3" || msg.EvidenceLogs[2] != "l5" {
		t.Errorf("expected tail l3..l5, got %v", msg.EvidenceLogs)
	}
}

func TestAttachEvidence_Disabled(t *testing.T) {
	p := &pb.AlertPayload{RedactedLogs: []string{"x"}}
	msg := &Message{Payload: p}
	AttachEvidence(msg, p, EvidenceConfig{Enabled: false, LogLines: 5})
	if msg.HasEvidence() {
		t.Error("disabled evidence must attach nothing")
	}
}

func TestEvidenceMetrics_FormatsValues(t *testing.T) {
	p := &pb.AlertPayload{
		Metrics: []*pb.MetricSeries{
			{MetricName: "container_memory_working_set_bytes", Unit: "bytes", Points: []*pb.DataPoint{{Value: 1024 * 1024 * 498}}},
		},
		PodMetas: []*pb.PodMeta{{RestartCount: 8, MemoryLimit: "512Mi"}},
	}
	facts := evidenceMetrics(p)
	joined := strings.Join(facts, " | ")
	if !strings.Contains(joined, "memory_working_set_bytes: 498.0MiB") {
		t.Errorf("byte formatting wrong: %q", joined)
	}
	if !strings.Contains(joined, "restarts: 8") {
		t.Errorf("restart fact missing: %q", joined)
	}
	if !strings.Contains(joined, "memory limit: 512Mi") {
		t.Errorf("memory limit fact missing: %q", joined)
	}
}

func TestLongLineTruncated(t *testing.T) {
	long := strings.Repeat("A", maxEvidenceLogLineLen+50)
	p := &pb.AlertPayload{RedactedLogs: []string{long}}
	msg := &Message{Payload: p}
	AttachEvidence(msg, p, EvidenceConfig{Enabled: true, LogLines: 5})
	if len(msg.EvidenceLogs) != 1 || len([]rune(msg.EvidenceLogs[0])) > maxEvidenceLogLineLen+1 {
		t.Errorf("oversize evidence line not truncated: len=%d", len(msg.EvidenceLogs[0]))
	}
}
