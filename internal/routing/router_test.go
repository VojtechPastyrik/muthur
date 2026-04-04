package routing

import (
	"testing"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

func TestRouter_FirstMatchWins(t *testing.T) {
	rules := []Rule{
		{
			Name:      "critical-all",
			Match:     Match{Severity: "critical"},
			Receivers: []string{"ops-telegram", "ops-discord"},
		},
		{
			Name:      "warning-discord",
			Match:     Match{Severity: "warning"},
			Receivers: []string{"ops-discord"},
		},
		{
			Name:      "info-silence",
			Match:     Match{Severity: "info"},
			Receivers: []string{},
		},
	}
	r := New(rules, zap.NewNop())

	targets := r.Route(&pb.AlertPayload{Severity: "critical", AlertName: "test"})
	if len(targets) != 2 || targets[0] != "ops-telegram" || targets[1] != "ops-discord" {
		t.Errorf("expected [ops-telegram ops-discord], got %v", targets)
	}

	targets = r.Route(&pb.AlertPayload{Severity: "warning", AlertName: "test"})
	if len(targets) != 1 || targets[0] != "ops-discord" {
		t.Errorf("expected [ops-discord], got %v", targets)
	}

	targets = r.Route(&pb.AlertPayload{Severity: "info", AlertName: "test"})
	if len(targets) != 0 {
		t.Errorf("expected empty, got %v", targets)
	}
}

func TestRouter_ClusterMatch(t *testing.T) {
	rules := []Rule{
		{
			Name:      "prod-critical",
			Match:     Match{Severity: "critical", ClusterID: "cluster-prod"},
			Receivers: []string{"oncall-pd"},
		},
		{
			Name:      "dev-all",
			Match:     Match{ClusterID: "cluster-dev"},
			Receivers: []string{"dev-discord"},
		},
	}
	r := New(rules, zap.NewNop())

	targets := r.Route(&pb.AlertPayload{Severity: "critical", ClusterId: "cluster-prod"})
	if len(targets) != 1 || targets[0] != "oncall-pd" {
		t.Errorf("expected [oncall-pd], got %v", targets)
	}

	targets = r.Route(&pb.AlertPayload{Severity: "warning", ClusterId: "cluster-dev"})
	if len(targets) != 1 || targets[0] != "dev-discord" {
		t.Errorf("expected [dev-discord], got %v", targets)
	}
}

func TestRouter_NoMatch(t *testing.T) {
	rules := []Rule{
		{
			Name:      "critical-only",
			Match:     Match{Severity: "critical"},
			Receivers: []string{"ops-telegram"},
		},
	}
	r := New(rules, zap.NewNop())

	targets := r.Route(&pb.AlertPayload{Severity: "warning", AlertName: "test"})
	if targets != nil {
		t.Errorf("expected nil, got %v", targets)
	}
}

func TestRouter_NamespaceMatch(t *testing.T) {
	rules := []Rule{
		{
			Name:      "kube-system",
			Match:     Match{Namespace: "kube-system"},
			Receivers: []string{"ops-slack"},
		},
	}
	r := New(rules, zap.NewNop())

	targets := r.Route(&pb.AlertPayload{Namespace: "kube-system", AlertName: "test"})
	if len(targets) != 1 || targets[0] != "ops-slack" {
		t.Errorf("expected [ops-slack], got %v", targets)
	}

	targets = r.Route(&pb.AlertPayload{Namespace: "default", AlertName: "test"})
	if targets != nil {
		t.Errorf("expected nil, got %v", targets)
	}
}
