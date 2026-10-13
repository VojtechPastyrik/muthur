package fleet

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

func testTenants(t *testing.T, clusters ...string) auth.TenantsProvider {
	t.Helper()
	var list []auth.Tenant
	for _, c := range clusters {
		list = append(list, auth.Tenant{ClusterID: c, TenantID: "acme"})
	}
	tn, err := auth.NewTenants(list)
	if err != nil {
		t.Fatalf("build tenants: %v", err)
	}
	return auth.StaticTenants{T: tn}
}

func revokedTenants(t *testing.T, cluster string) auth.TenantsProvider {
	t.Helper()
	tn, err := auth.NewTenants([]auth.Tenant{{ClusterID: cluster, TenantID: "acme", Revoked: true}})
	if err != nil {
		t.Fatalf("build tenants: %v", err)
	}
	return auth.StaticTenants{T: tn}
}

// collect returns a NotifyFunc appending to the slice it returns a pointer to.
func collect() (NotifyFunc, *[]Event) {
	var got []Event
	return func(ev Event) { got = append(got, ev) }, &got
}

func beat(t *testing.T, tr *Tracker, cluster string, interval int32) {
	t.Helper()
	err := tr.Record(context.Background(), cluster, &pb.HeartbeatRequest{
		ClusterId:        cluster,
		IntervalSeconds:  interval,
		CollectorVersion: "0.11.0",
	})
	if err != nil {
		t.Fatalf("record heartbeat: %v", err)
	}
}

func TestWatchdogPagesOnceThenRecovers(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	logger := zap.NewNop()
	tr := NewTracker(st, time.Hour, logger)
	notify, got := collect()
	w := NewWatchdog(st, testTenants(t, "prod"), notify, WatchdogConfig{
		Enabled:         true,
		StaleMultiplier: 3,
		StaleFloor:      time.Minute,
	}, logger)

	beat(t, tr, "prod", 60)
	now := time.Now()

	// Fresh beat: no event.
	w.Scan(context.Background(), now)
	if len(*got) != 0 {
		t.Fatalf("expected no event for a fresh beat, got %v", *got)
	}

	// Silent past 3x60s.
	down := now.Add(4 * time.Minute)
	w.Scan(context.Background(), down)
	if len(*got) != 1 || (*got)[0].Status != StatusDown {
		t.Fatalf("expected one down event, got %v", *got)
	}

	// Still silent: must NOT page again. An outage is one notification.
	w.Scan(context.Background(), down.Add(10*time.Minute))
	if len(*got) != 1 {
		t.Fatalf("expected no repeat page while still down, got %d events", len(*got))
	}

	// Beat returns.
	beat(t, tr, "prod", 60)
	w.Scan(context.Background(), time.Now())
	if len(*got) != 2 || (*got)[1].Status != StatusRecovered {
		t.Fatalf("expected recovery event, got %v", *got)
	}
}

func TestWatchdogRetiresRevokedTenantWithoutPaging(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	logger := zap.NewNop()
	tr := NewTracker(st, time.Hour, logger)
	notify, got := collect()

	beat(t, tr, "gone", 60)

	// The cluster was decommissioned: tenant flipped to revoked. Even though
	// the collector has been silent for an hour, nobody must be paged.
	w := NewWatchdog(st, revokedTenants(t, "gone"), notify, WatchdogConfig{
		Enabled: true, StaleMultiplier: 3, StaleFloor: time.Minute,
	}, logger)
	w.Scan(context.Background(), time.Now().Add(time.Hour))

	if len(*got) != 0 {
		t.Fatalf("revoked tenant must not page, got %v", *got)
	}
	if _, ok, _ := st.Get(context.Background(), key("gone")); ok {
		t.Fatal("revoked tenant's heartbeat record must be purged from the roster")
	}
}

func TestWatchdogRetiresTenantRemovedFromConfig(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	logger := zap.NewNop()
	tr := NewTracker(st, time.Hour, logger)
	notify, got := collect()

	beat(t, tr, "deleted", 60)

	// Tenant hard-deleted from the config file — the other offboarding path.
	w := NewWatchdog(st, testTenants(t, "someone-else"), notify, WatchdogConfig{
		Enabled: true, StaleMultiplier: 3, StaleFloor: time.Minute,
	}, logger)
	w.Scan(context.Background(), time.Now().Add(time.Hour))

	if len(*got) != 0 {
		t.Fatalf("removed tenant must not page, got %v", *got)
	}
	if _, ok, _ := st.Get(context.Background(), key("deleted")); ok {
		t.Fatal("removed tenant's heartbeat record must be purged")
	}
}

func TestWatchdogHonoursGracefulShutdown(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	logger := zap.NewNop()
	tr := NewTracker(st, time.Hour, logger)
	notify, got := collect()

	err := tr.Record(context.Background(), "bye", &pb.HeartbeatRequest{
		ClusterId:       "bye",
		IntervalSeconds: 60,
		ShuttingDown:    true,
	})
	if err != nil {
		t.Fatalf("record goodbye: %v", err)
	}

	w := NewWatchdog(st, testTenants(t, "bye"), notify, WatchdogConfig{
		Enabled: true, StaleMultiplier: 3, StaleFloor: time.Minute,
	}, logger)
	w.Scan(context.Background(), time.Now().Add(time.Hour))

	if len(*got) != 0 {
		t.Fatalf("a collector that announced shutdown must not page, got %v", *got)
	}
}

func TestWatchdogStaleFloorProtectsAgainstTinyInterval(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	logger := zap.NewNop()
	tr := NewTracker(st, time.Hour, logger)
	notify, got := collect()

	// A collector reporting interval 0 (misconfigured or an old build) must
	// not be declared down a second after its beat.
	beat(t, tr, "zero", 0)

	w := NewWatchdog(st, testTenants(t, "zero"), notify, WatchdogConfig{
		Enabled: true, StaleMultiplier: 3, StaleFloor: 10 * time.Minute,
	}, logger)
	w.Scan(context.Background(), time.Now().Add(5*time.Minute))

	if len(*got) != 0 {
		t.Fatalf("stale floor must suppress a page at 5m with a 10m floor, got %v", *got)
	}

	w.Scan(context.Background(), time.Now().Add(11*time.Minute))
	if len(*got) != 1 || (*got)[0].Status != StatusDown {
		t.Fatalf("expected a page past the stale floor, got %v", *got)
	}
}

func TestTrackerRejectsClusterIDMismatch(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	tr := NewTracker(st, time.Hour, zap.NewNop())

	// The body claims another tenant's cluster. A collector must not be able
	// to keep another cluster's liveness record fresh and mask its outage.
	err := tr.Record(context.Background(), "mine", &pb.HeartbeatRequest{ClusterId: "yours"})
	if err == nil {
		t.Fatal("expected a cluster_id mismatch to be refused")
	}
}

func TestTrackerRejectsMissingIdentity(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	tr := NewTracker(st, time.Hour, zap.NewNop())
	if err := tr.Record(context.Background(), "", &pb.HeartbeatRequest{}); err == nil {
		t.Fatal("expected a heartbeat without verified identity to be refused")
	}
}

func TestSyntheticAlertShape(t *testing.T) {
	now := time.Now()
	ev := Event{
		Status: StatusDown,
		Age:    5 * time.Minute,
		State:  State{ClusterID: "prod", LastSeen: now.Add(-5 * time.Minute).Unix(), Version: "0.11.0"},
	}
	p := SyntheticAlert(ev, now)
	if p.AlertName != AlertName || p.Severity != "critical" || p.Status != "firing" {
		t.Fatalf("unexpected down alert shape: %+v", p)
	}
	if p.ClusterId != "prod" {
		t.Fatalf("cluster id not carried: %+v", p)
	}

	rec := SyntheticAlert(Event{Status: StatusRecovered, State: ev.State}, now)
	if rec.Status != "resolved" {
		t.Fatalf("recovery must render as resolved, got %q", rec.Status)
	}
}

func beatWithPipeline(t *testing.T, tr *Tracker, cluster string, pipelineSeen int64) {
	t.Helper()
	err := tr.Record(context.Background(), cluster, &pb.HeartbeatRequest{
		ClusterId:        cluster,
		IntervalSeconds:  60,
		PipelineLastSeen: pipelineSeen,
	})
	if err != nil {
		t.Fatalf("record heartbeat: %v", err)
	}
}

func TestPipelineNeverPagesWhenNotConfigured(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	logger := zap.NewNop()
	tr := NewTracker(st, time.Hour, logger)
	notify, got := collect()

	// pipeline_last_seen == 0: the operator never routed Watchdog. Paging
	// about a probe nobody opted into would be a self-inflicted false alarm.
	beatWithPipeline(t, tr, "prod", 0)

	w := NewWatchdog(st, testTenants(t, "prod"), notify, WatchdogConfig{
		Enabled: true, StaleMultiplier: 3, StaleFloor: time.Minute,
		PipelineStale: 10 * time.Minute,
	}, logger)
	w.Scan(context.Background(), time.Now())

	if len(*got) != 0 {
		t.Fatalf("an unconfigured pipeline probe must stay silent, got %v", *got)
	}
}

func TestPipelineDownWhileCollectorHealthy(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	logger := zap.NewNop()
	tr := NewTracker(st, time.Hour, logger)
	notify, got := collect()
	now := time.Now()

	// The collector is beating normally, but Watchdog last arrived 30 minutes
	// ago — Prometheus or AlertManager behind it is broken and alerts raised
	// in that cluster are being lost.
	beatWithPipeline(t, tr, "prod", now.Add(-30*time.Minute).Unix())

	w := NewWatchdog(st, testTenants(t, "prod"), notify, WatchdogConfig{
		Enabled: true, StaleMultiplier: 3, StaleFloor: time.Minute,
		PipelineStale: 10 * time.Minute,
	}, logger)
	w.Scan(context.Background(), now)

	if len(*got) != 1 || (*got)[0].Status != StatusPipelineDown {
		t.Fatalf("expected a pipeline-down event, got %v", *got)
	}

	// Still broken: must not re-page.
	w.Scan(context.Background(), now.Add(time.Minute))
	if len(*got) != 1 {
		t.Fatalf("pipeline outage must page once, got %d events", len(*got))
	}

	// Watchdog starts arriving again.
	beatWithPipeline(t, tr, "prod", time.Now().Unix())
	w.Scan(context.Background(), time.Now())
	if len(*got) != 2 || (*got)[1].Status != StatusPipelineRecovered {
		t.Fatalf("expected a pipeline-recovered event, got %v", *got)
	}
}

func TestPipelineVerdictSkippedWhenCollectorIsDown(t *testing.T) {
	st := store.NewMemory()
	defer st.Close()
	logger := zap.NewNop()
	tr := NewTracker(st, time.Hour, logger)
	notify, got := collect()
	now := time.Now()

	beatWithPipeline(t, tr, "prod", now.Add(-time.Hour).Unix())

	w := NewWatchdog(st, testTenants(t, "prod"), notify, WatchdogConfig{
		Enabled: true, StaleMultiplier: 3, StaleFloor: time.Minute,
		PipelineStale: 10 * time.Minute,
	}, logger)
	// Collector silent for an hour: one down page, and no separate pipeline
	// page — a stale probe adds nothing once the collector itself is gone.
	w.Scan(context.Background(), now.Add(time.Hour))

	if len(*got) != 1 || (*got)[0].Status != StatusDown {
		t.Fatalf("expected only the collector-down event, got %v", *got)
	}
}

func TestPipelineAlertRendersUnderItsOwnName(t *testing.T) {
	now := time.Now()
	ev := Event{
		Status: StatusPipelineDown,
		Age:    30 * time.Minute,
		State:  State{ClusterID: "prod", LastSeen: now.Unix(), PipelineLastSeen: now.Add(-30 * time.Minute).Unix()},
	}
	p := SyntheticAlert(ev, now)
	if p.AlertName != PipelineAlertName {
		t.Fatalf("expected %q, got %q", PipelineAlertName, p.AlertName)
	}
	if p.Severity != "critical" || p.Status != "firing" {
		t.Fatalf("a broken alerting path is a critical firing alert: %+v", p)
	}
}
