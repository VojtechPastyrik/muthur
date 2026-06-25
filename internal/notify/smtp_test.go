package notify

import (
	"strings"
	"testing"

	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

func TestNewSMTP_Validation(t *testing.T) {
	if _, err := newSMTP("e", map[string]string{"from": "a@b.c", "to": "x@y.z"}); err == nil {
		t.Error("missing host should error")
	}
	if _, err := newSMTP("e", map[string]string{"host": "h", "from": "a@b.c"}); err == nil {
		t.Error("missing to should error")
	}
	n, err := newSMTP("e", map[string]string{"host": "h", "from": "a@b.c", "to": "x@y.z, w@y.z"})
	if err != nil {
		t.Fatalf("valid config errored: %v", err)
	}
	if n.Name() != "e" {
		t.Errorf("name = %q", n.Name())
	}
}

func TestBuildEmail_Content(t *testing.T) {
	msg := &Message{
		Payload: &pb.AlertPayload{ClusterId: "c1", AlertName: "OOM", Namespace: "ns", Severity: "critical"},
		Analysis: &evaluator.Analysis{
			RootCause: "memory limit too low", Action: "raise limit",
			Confidence: "high", Grounding: "stated",
		},
		EvidenceLogs:    []string{"FATAL: out of memory"},
		EvidenceMetrics: []string{"restarts: 8"},
	}
	out := buildEmail("muthur@x.io", []string{"oncall@x.io"}, msg)

	for _, want := range []string{
		"Subject: [CRITICAL] c1 / OOM",
		"To: oncall@x.io",
		"Root cause: memory limit too low",
		"high confidence · stated",
		"--- Evidence ---",
		"restarts: 8",
		"FATAL: out of memory",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("email missing %q\n---\n%s", want, out)
		}
	}
}

func TestBuildEmail_Resolved(t *testing.T) {
	msg := &Message{Payload: &pb.AlertPayload{ClusterId: "c1", AlertName: "OOM", Status: "resolved"}}
	out := buildEmail("m@x.io", []string{"o@x.io"}, msg)
	if !strings.Contains(out, "Alert has cleared.") {
		t.Errorf("resolved email missing cleared notice:\n%s", out)
	}
	if !strings.Contains(out, "Subject: [RESOLVED]") {
		t.Errorf("resolved subject wrong:\n%s", out)
	}
}
