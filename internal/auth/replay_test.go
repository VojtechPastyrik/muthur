package auth

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/VojtechPastyrik/muthur/internal/store"
)

const validNonce = "0123456789abcdef0123456789abcdef" // 32 hex chars, single-use in tests

func newGuard(t *testing.T) *ReplayGuard {
	t.Helper()
	return NewReplayGuard(store.NewMemory(), 5*time.Minute, "muthur:")
}

func tsStr(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return strconv.FormatInt(ts.Unix(), 10)
}

func TestVerify_HappyPath(t *testing.T) {
	g := newGuard(t)
	id := &Identity{ClusterID: "c1"}

	if err := g.Verify(context.Background(), id, tsStr(time.Now()), validNonce); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_RejectsReusedNonce(t *testing.T) {
	g := newGuard(t)
	id := &Identity{ClusterID: "c1"}

	if err := g.Verify(context.Background(), id, tsStr(time.Now()), validNonce); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	err := g.Verify(context.Background(), id, tsStr(time.Now()), validNonce)
	if !errors.Is(err, ErrReplayNonceReused) {
		t.Errorf("err = %v, want ErrReplayNonceReused", err)
	}
}

func TestVerify_NonceScopedToIdentity(t *testing.T) {
	g := newGuard(t)

	if err := g.Verify(context.Background(), &Identity{ClusterID: "a"}, tsStr(time.Now()), validNonce); err != nil {
		t.Fatalf("identity a: %v", err)
	}
	if err := g.Verify(context.Background(), &Identity{ClusterID: "b"}, tsStr(time.Now()), validNonce); err != nil {
		t.Errorf("identity b reusing nonce across identities: %v (must succeed)", err)
	}
}

func TestVerify_RejectsFutureTimestampOutsideWindow(t *testing.T) {
	g := newGuard(t)
	g.now = func() time.Time { return time.Unix(1_000_000, 0) }

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, tsStr(time.Unix(1_000_000+10*60, 0)), validNonce)
	if !errors.Is(err, ErrReplayClockSkew) {
		t.Errorf("err = %v, want ErrReplayClockSkew", err)
	}
}

func TestVerify_RejectsPastTimestampOutsideWindow(t *testing.T) {
	g := newGuard(t)
	g.now = func() time.Time { return time.Unix(1_000_000, 0) }

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, tsStr(time.Unix(1_000_000-10*60, 0)), validNonce)
	if !errors.Is(err, ErrReplayClockSkew) {
		t.Errorf("err = %v, want ErrReplayClockSkew", err)
	}
}

func TestVerify_AcceptsTimestampInsideWindow(t *testing.T) {
	g := newGuard(t)
	g.now = func() time.Time { return time.Unix(1_000_000, 0) }

	if err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, tsStr(time.Unix(1_000_000+4*60, 0)), validNonce); err != nil {
		t.Errorf("Verify inside window: %v", err)
	}
}

func TestVerify_MissingTimestamp(t *testing.T) {
	g := newGuard(t)

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, "", validNonce)
	if !errors.Is(err, ErrReplayMissingTimestamp) {
		t.Errorf("err = %v, want ErrReplayMissingTimestamp", err)
	}
}

func TestVerify_MalformedTimestamp(t *testing.T) {
	g := newGuard(t)

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, "not-a-number", validNonce)
	if !errors.Is(err, ErrReplayBadTimestamp) {
		t.Errorf("err = %v, want ErrReplayBadTimestamp", err)
	}
}

func TestVerify_MissingNonce(t *testing.T) {
	g := newGuard(t)

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, tsStr(time.Now()), "")
	if !errors.Is(err, ErrReplayMissingNonce) {
		t.Errorf("err = %v, want ErrReplayMissingNonce", err)
	}
}

func TestVerify_TooShortNonce(t *testing.T) {
	g := newGuard(t)

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, tsStr(time.Now()), strings.Repeat("a", minNonceHexLen-1))
	if !errors.Is(err, ErrReplayBadNonce) {
		t.Errorf("err = %v, want ErrReplayBadNonce", err)
	}
}

func TestVerify_NonHexNonce(t *testing.T) {
	g := newGuard(t)

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, tsStr(time.Now()), strings.Repeat("z", minNonceHexLen))
	if !errors.Is(err, ErrReplayBadNonce) {
		t.Errorf("err = %v, want ErrReplayBadNonce", err)
	}
}

func TestVerify_NilIdentity(t *testing.T) {
	g := newGuard(t)

	err := g.Verify(context.Background(), nil, tsStr(time.Now()), validNonce)
	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("err = %v, want ErrNoIdentity", err)
	}
}

func TestVerify_DefaultWindowOnNonPositive(t *testing.T) {
	g := NewReplayGuard(store.NewMemory(), 0, "muthur:")
	if g.window <= 0 {
		t.Errorf("window = %v, want >0 after default fallback", g.window)
	}
}
