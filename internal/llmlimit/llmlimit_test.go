package llmlimit

import (
	"testing"

	"go.uber.org/zap"
)

// TestNil_Unlimited confirms a nil limiter (disabled config) never throttles.
func TestNil_Unlimited(t *testing.T) {
	var l *Limiter
	for i := 0; i < 1000; i++ {
		if !l.Acquire("test-cluster") {
			t.Fatal("nil limiter must always allow")
		}
		l.Release("test-cluster")
	}
}

// TestRateCeiling proves the token bucket caps the burst: with burst=3 and a
// negligible refill over the test window, the 4th immediate call is denied.
func TestRateCeiling(t *testing.T) {
	l := New(1 /* per minute */, 3 /* burst */, 100 /* concurrency */, zap.NewNop())
	for i := 0; i < 3; i++ {
		if !l.Acquire("test-cluster") {
			t.Fatalf("call %d within burst should be allowed", i+1)
		}
		l.Release("test-cluster")
	}
	if l.Acquire("test-cluster") {
		t.Fatal("call beyond burst should be denied by the rate ceiling")
	}
}

// TestConcurrencyCeiling proves the in-flight cap denies the (n+1)th concurrent
// holder, and that releasing frees a slot.
func TestConcurrencyCeiling(t *testing.T) {
	l := New(10000 /* effectively unlimited rate */, 10000, 2 /* concurrency */, zap.NewNop())
	if !l.Acquire("test-cluster") || !l.Acquire("test-cluster") {
		t.Fatal("first two concurrent acquires should succeed")
	}
	if l.Acquire("test-cluster") {
		t.Fatal("third concurrent acquire should be denied by the concurrency cap")
	}
	l.Release("test-cluster")
	if !l.Acquire("test-cluster") {
		t.Fatal("after a release, a slot should be available again")
	}
}

// TestDisabledWhenNonPositive confirms non-positive limits disable the limiter.
func TestDisabledWhenNonPositive(t *testing.T) {
	if New(0, 5, 5, zap.NewNop()) != nil {
		t.Error("zero calls-per-minute should disable (nil) the limiter")
	}
	if New(5, 5, 0, zap.NewNop()) != nil {
		t.Error("zero concurrency should disable (nil) the limiter")
	}
}

// TestPool_PerTenantIsolation verifies one tenant exhausting its bucket does
// not lock another tenant out — the regression-guard for the multi-tenant
// cost-isolation invariant.
func TestPool_PerTenantIsolation(t *testing.T) {
	pool := NewPool(60, 1 /* burst=1 so a single Acquire exhausts the bucket */, 1, zap.NewNop())

	if !pool.Acquire("tenant-a") {
		t.Fatal("tenant-a's first acquire should succeed")
	}
	// tenant-a is now at its concurrency ceiling.
	if pool.Acquire("tenant-a") {
		t.Fatal("tenant-a's second acquire should be denied — its bucket is full")
	}
	// tenant-b has its own bucket and must be unaffected.
	if !pool.Acquire("tenant-b") {
		t.Fatal("tenant-b must not be blocked by tenant-a's saturation")
	}
}

// TestPool_DisabledWhenNonPositive confirms a non-positive ceiling yields a
// nil Pool (unlimited), mirroring New's behaviour.
func TestPool_DisabledWhenNonPositive(t *testing.T) {
	if NewPool(0, 5, 5, zap.NewNop()) != nil {
		t.Error("zero calls-per-minute should disable (nil) the pool")
	}
	if NewPool(5, 5, 0, zap.NewNop()) != nil {
		t.Error("zero concurrency should disable (nil) the pool")
	}
}

// TestPool_NilSafeAcquireRelease asserts a nil Pool behaves as unlimited.
func TestPool_NilSafeAcquireRelease(t *testing.T) {
	var pool *Pool
	if !pool.Acquire("x") {
		t.Fatal("nil pool must allow all acquires")
	}
	pool.Release("x") // must not panic
}
