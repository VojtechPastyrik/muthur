package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

func newReq(t *testing.T, ts time.Time, nonce string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	if !ts.IsZero() {
		r.Header.Set(HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
	}
	if nonce != "" {
		r.Header.Set(HeaderNonce, nonce)
	}
	return r
}

func TestVerify_HappyPath(t *testing.T) {
	g := newGuard(t)
	id := &Identity{ClusterID: "c1"}
	r := newReq(t, time.Now(), validNonce)

	if err := g.Verify(context.Background(), id, r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_RejectsReusedNonce(t *testing.T) {
	g := newGuard(t)
	id := &Identity{ClusterID: "c1"}

	// First call burns the nonce.
	if err := g.Verify(context.Background(), id, newReq(t, time.Now(), validNonce)); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	// Second call with the same nonce must be rejected, even with a fresh
	// timestamp.
	err := g.Verify(context.Background(), id, newReq(t, time.Now(), validNonce))
	if !errors.Is(err, ErrReplayNonceReused) {
		t.Errorf("err = %v, want ErrReplayNonceReused", err)
	}
}

func TestVerify_NonceScopedToIdentity(t *testing.T) {
	g := newGuard(t)

	if err := g.Verify(context.Background(), &Identity{ClusterID: "a"}, newReq(t, time.Now(), validNonce)); err != nil {
		t.Fatalf("identity a: %v", err)
	}
	// Same nonce, different identity ⇒ separate key, must succeed.
	if err := g.Verify(context.Background(), &Identity{ClusterID: "b"}, newReq(t, time.Now(), validNonce)); err != nil {
		t.Errorf("identity b reusing nonce across identities: %v (must succeed)", err)
	}
}

func TestVerify_RejectsFutureTimestampOutsideWindow(t *testing.T) {
	g := newGuard(t)
	g.now = func() time.Time { return time.Unix(1_000_000, 0) }

	r := newReq(t, time.Unix(1_000_000+10*60, 0), validNonce) // +10 min
	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, r)
	if !errors.Is(err, ErrReplayClockSkew) {
		t.Errorf("err = %v, want ErrReplayClockSkew", err)
	}
}

func TestVerify_RejectsPastTimestampOutsideWindow(t *testing.T) {
	g := newGuard(t)
	g.now = func() time.Time { return time.Unix(1_000_000, 0) }

	r := newReq(t, time.Unix(1_000_000-10*60, 0), validNonce) // -10 min
	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, r)
	if !errors.Is(err, ErrReplayClockSkew) {
		t.Errorf("err = %v, want ErrReplayClockSkew", err)
	}
}

func TestVerify_AcceptsTimestampInsideWindow(t *testing.T) {
	g := newGuard(t)
	g.now = func() time.Time { return time.Unix(1_000_000, 0) }

	// 4 minutes ahead — inside the 5-minute window.
	r := newReq(t, time.Unix(1_000_000+4*60, 0), validNonce)
	if err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, r); err != nil {
		t.Errorf("Verify inside window: %v", err)
	}
}

func TestVerify_MissingTimestamp(t *testing.T) {
	g := newGuard(t)
	r := newReq(t, time.Time{}, validNonce) // no timestamp

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, r)
	if !errors.Is(err, ErrReplayMissingTimestamp) {
		t.Errorf("err = %v, want ErrReplayMissingTimestamp", err)
	}
}

func TestVerify_MalformedTimestamp(t *testing.T) {
	g := newGuard(t)
	r := newReq(t, time.Time{}, validNonce)
	r.Header.Set(HeaderTimestamp, "not-a-number")

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, r)
	if !errors.Is(err, ErrReplayBadTimestamp) {
		t.Errorf("err = %v, want ErrReplayBadTimestamp", err)
	}
}

func TestVerify_MissingNonce(t *testing.T) {
	g := newGuard(t)
	r := newReq(t, time.Now(), "")

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, r)
	if !errors.Is(err, ErrReplayMissingNonce) {
		t.Errorf("err = %v, want ErrReplayMissingNonce", err)
	}
}

func TestVerify_TooShortNonce(t *testing.T) {
	g := newGuard(t)
	r := newReq(t, time.Now(), strings.Repeat("a", minNonceHexLen-1))

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, r)
	if !errors.Is(err, ErrReplayBadNonce) {
		t.Errorf("err = %v, want ErrReplayBadNonce", err)
	}
}

func TestVerify_NonHexNonce(t *testing.T) {
	g := newGuard(t)
	r := newReq(t, time.Now(), strings.Repeat("z", minNonceHexLen))

	err := g.Verify(context.Background(), &Identity{ClusterID: "c"}, r)
	if !errors.Is(err, ErrReplayBadNonce) {
		t.Errorf("err = %v, want ErrReplayBadNonce", err)
	}
}

func TestVerify_NilIdentity(t *testing.T) {
	g := newGuard(t)
	r := newReq(t, time.Now(), validNonce)

	err := g.Verify(context.Background(), nil, r)
	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("err = %v, want ErrNoIdentity", err)
	}
}

func TestVerify_DefaultWindowOnNonPositive(t *testing.T) {
	// Window <= 0 must fall back to a sensible default rather than disabling
	// replay protection altogether.
	g := NewReplayGuard(store.NewMemory(), 0, "muthur:")
	if g.window <= 0 {
		t.Errorf("window = %v, want >0 after default fallback", g.window)
	}
}
