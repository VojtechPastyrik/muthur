package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

const sampleYAMLActive = `
tenants:
  - clusterId: c1
    tenantId: v1
    bootstrapTokenHash: deadbeef
    bootstrapExpiresAt: 2099-01-01T00:00:00Z
    revoked: false
    certDuration: 24h
`

const sampleYAMLRevoked = `
tenants:
  - clusterId: c1
    tenantId: v1
    bootstrapTokenHash: deadbeef
    bootstrapExpiresAt: 2099-01-01T00:00:00Z
    revoked: true
    certDuration: 24h
`

// writeFile writes content and bumps the mtime so the reloader's stat-poll
// notices the change. Tests can't rely on a sub-second mtime bump being
// visible on every filesystem (HFS+, some NFS), so we force it.
func writeFile(t *testing.T, path, content string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

func TestTenantsReloader_InitialLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.yaml")
	writeFile(t, path, sampleYAMLActive, time.Now())

	r, err := NewTenantsReloader(path, 50*time.Millisecond, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("NewTenantsReloader: %v", err)
	}
	defer r.Stop()
	r.Start()

	tenants := r.Current()
	if tenants == nil || tenants.Len() != 1 {
		t.Fatalf("want 1 tenant, got %v", tenants)
	}
	tenant, ok := tenants.Lookup("c1")
	if !ok || tenant.Revoked {
		t.Fatalf("want active c1, got ok=%v revoked=%v", ok, tenant.Revoked)
	}
}

func TestTenantsReloader_PicksUpRevocation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.yaml")
	start := time.Now()
	writeFile(t, path, sampleYAMLActive, start)

	r, err := NewTenantsReloader(path, 50*time.Millisecond, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("NewTenantsReloader: %v", err)
	}
	defer r.Stop()
	r.Start()

	// Flip to revoked with a bumped mtime so the poller stat sees a change.
	writeFile(t, path, sampleYAMLRevoked, start.Add(2*time.Second))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		tenant, ok := r.Current().Lookup("c1")
		if ok && tenant.Revoked {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("reloader did not pick up revocation within 2s")
}

func TestTenantsReloader_BadYAMLKeepsPreviousSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.yaml")
	start := time.Now()
	writeFile(t, path, sampleYAMLActive, start)

	r, err := NewTenantsReloader(path, 50*time.Millisecond, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("NewTenantsReloader: %v", err)
	}
	defer r.Stop()
	r.Start()

	// Corrupt the file. Reloader must keep serving the previous snapshot
	// rather than wiping the authorisation list — a torn write from a
	// concurrent ConfigMap update cannot lock out every collector.
	writeFile(t, path, "tenants: {{{", start.Add(2*time.Second))

	time.Sleep(200 * time.Millisecond)

	tenant, ok := r.Current().Lookup("c1")
	if !ok || tenant.Revoked {
		t.Fatalf("previous snapshot must survive bad YAML; got ok=%v revoked=%v", ok, tenant.Revoked)
	}
}

func TestTenantsReloader_MissingFileAtStartupFailsFast(t *testing.T) {
	_, err := NewTenantsReloader("/no/such/file", 50*time.Millisecond, zaptest.NewLogger(t))
	if err == nil {
		t.Fatal("expected startup to fail on missing config file")
	}
}
