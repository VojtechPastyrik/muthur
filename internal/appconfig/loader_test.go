package appconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_FullConfig(t *testing.T) {
	content := `receivers:
  - name: ops-discord
    type: discord
    config:
      webhook_url: "$env:OPS_DISCORD_URL"
  - name: dev-discord
    type: discord
    config:
      webhook_url: "$env:DEV_DISCORD_URL"
  - name: oncall-pd
    type: pagerduty
    config:
      routing_key: "$env:ONCALL_PD_KEY"
routing:
  rules:
    - name: critical
      match:
        severity: critical
      receivers: [ops-discord, oncall-pd]
    - name: dev-warnings
      match:
        severity: warning
        cluster_id: cluster-dev
      receivers: [dev-discord]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "muthur.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	fc, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(fc.Receivers) != 3 {
		t.Errorf("expected 3 receivers, got %d", len(fc.Receivers))
	}
	if fc.Receivers[0].Name != "ops-discord" {
		t.Errorf("unexpected first receiver: %s", fc.Receivers[0].Name)
	}
	if fc.Receivers[0].Type != "discord" {
		t.Errorf("unexpected first receiver type: %s", fc.Receivers[0].Type)
	}
	if fc.Receivers[0].Config["webhook_url"] != "$env:OPS_DISCORD_URL" {
		t.Errorf("unexpected webhook_url: %s", fc.Receivers[0].Config["webhook_url"])
	}

	if len(fc.Routing.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(fc.Routing.Rules))
	}
	if len(fc.Routing.Rules[0].Receivers) != 2 {
		t.Errorf("expected 2 receivers in first rule, got %d", len(fc.Routing.Rules[0].Receivers))
	}
	if fc.Routing.Rules[0].Receivers[0] != "ops-discord" {
		t.Errorf("expected ops-discord, got %s", fc.Routing.Rules[0].Receivers[0])
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/muthur.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("not: valid: yaml: ["), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid yaml")
	}
}
