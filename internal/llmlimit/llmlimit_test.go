package llmlimit

import (
	"testing"

	"go.uber.org/zap"
)

// TestNil_Unlimited confirms a nil limiter (disabled config) never throttles.
func TestNil_Unlimited(t *testing.T) {
	var l *Limiter
	for i := 0; i < 1000; i++ {
		if !l.Acquire() {
			t.Fatal("nil limiter must always allow")
		}
		l.Release()
	}
}

// TestRateCeiling proves the token bucket caps the burst: with burst=3 and a
// negligible refill over the test window, the 4th immediate call is denied.
func TestRateCeiling(t *testing.T) {
	l := New(1 /* per minute */, 3 /* burst */, 100 /* concurrency */, zap.NewNop())
	for i := 0; i < 3; i++ {
		if !l.Acquire() {
			t.Fatalf("call %d within burst should be allowed", i+1)
		}
		l.Release()
	}
	if l.Acquire() {
		t.Fatal("call beyond burst should be denied by the rate ceiling")
	}
}

// TestConcurrencyCeiling proves the in-flight cap denies the (n+1)th concurrent
// holder, and that releasing frees a slot.
func TestConcurrencyCeiling(t *testing.T) {
	l := New(10000 /* effectively unlimited rate */, 10000, 2 /* concurrency */, zap.NewNop())
	if !l.Acquire() || !l.Acquire() {
		t.Fatal("first two concurrent acquires should succeed")
	}
	if l.Acquire() {
		t.Fatal("third concurrent acquire should be denied by the concurrency cap")
	}
	l.Release()
	if !l.Acquire() {
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
