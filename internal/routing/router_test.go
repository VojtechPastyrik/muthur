package routing

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur-central/proto"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "routing.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRouter_FirstMatchWins(t *testing.T) {
	config := `rules:
  - name: critical-all
    match:
      severity: critical
    notify: [telegram, discord]
  - name: warning-discord
    match:
      severity: warning
    notify: [discord]
  - name: info-silence
    match:
      severity: info
    notify: []
`
	r, err := NewRouter(writeConfig(t, config), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	targets := r.Route(&pb.AlertPayload{Severity: "critical", AlertName: "test"})
	if len(targets) != 2 || targets[0] != "telegram" || targets[1] != "discord" {
		t.Errorf("expected [telegram discord], got %v", targets)
	}

	targets = r.Route(&pb.AlertPayload{Severity: "warning", AlertName: "test"})
	if len(targets) != 1 || targets[0] != "discord" {
		t.Errorf("expected [discord], got %v", targets)
	}

	targets = r.Route(&pb.AlertPayload{Severity: "info", AlertName: "test"})
	if len(targets) != 0 {
		t.Errorf("expected empty, got %v", targets)
	}
}

func TestRouter_ClusterMatch(t *testing.T) {
	config := `rules:
  - name: prod-critical
    match:
      severity: critical
      cluster_id: cluster-prod
    notify: [pagerduty]
  - name: dev-all
    match:
      cluster_id: cluster-dev
    notify: [discord]
`
	r, err := NewRouter(writeConfig(t, config), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	targets := r.Route(&pb.AlertPayload{Severity: "critical", ClusterId: "cluster-prod"})
	if len(targets) != 1 || targets[0] != "pagerduty" {
		t.Errorf("expected [pagerduty], got %v", targets)
	}

	targets = r.Route(&pb.AlertPayload{Severity: "warning", ClusterId: "cluster-dev"})
	if len(targets) != 1 || targets[0] != "discord" {
		t.Errorf("expected [discord], got %v", targets)
	}
}

func TestRouter_NoMatch(t *testing.T) {
	config := `rules:
  - name: critical-only
    match:
      severity: critical
    notify: [telegram]
`
	r, err := NewRouter(writeConfig(t, config), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	targets := r.Route(&pb.AlertPayload{Severity: "warning", AlertName: "test"})
	if targets != nil {
		t.Errorf("expected nil, got %v", targets)
	}
}

func TestRouter_NamespaceMatch(t *testing.T) {
	config := `rules:
  - name: kube-system
    match:
      namespace: kube-system
    notify: [slack]
`
	r, err := NewRouter(writeConfig(t, config), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	targets := r.Route(&pb.AlertPayload{Namespace: "kube-system", AlertName: "test"})
	if len(targets) != 1 || targets[0] != "slack" {
		t.Errorf("expected [slack], got %v", targets)
	}

	targets = r.Route(&pb.AlertPayload{Namespace: "default", AlertName: "test"})
	if targets != nil {
		t.Errorf("expected nil, got %v", targets)
	}
}
