package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/VojtechPastyrik/muthur/internal/store"
)

// Replay-protection HTTP headers. The collector signs nothing here — the mTLS
// channel already provides integrity and authenticity. These headers exist
// only to make every request fresh and single-use, so an attacker who captures
// a ciphertext (e.g. a TLS-recorded session) cannot replay it later.
const (
	HeaderTimestamp = "X-Muthur-Timestamp"
	HeaderNonce     = "X-Muthur-Nonce"

	// Minimum nonce length, in hex characters. 32 hex = 16 bytes = 128 bits,
	// the cheapest size that makes random collisions negligible.
	minNonceHexLen = 32
)

// Replay-related sentinel errors. Callers should map these to 401/400/409 as
// appropriate; the package itself avoids the http layer to stay testable.
var (
	ErrReplayMissingTimestamp = errors.New("auth: missing timestamp header")
	ErrReplayBadTimestamp     = errors.New("auth: malformed timestamp header")
	ErrReplayClockSkew        = errors.New("auth: timestamp outside window")
	ErrReplayMissingNonce     = errors.New("auth: missing nonce header")
	ErrReplayBadNonce         = errors.New("auth: malformed nonce header")
	ErrReplayNonceReused      = errors.New("auth: nonce already seen")
)

// ReplayGuard verifies request freshness and uniqueness using a timestamp
// window and a single-use nonce cache. It is safe for concurrent use across
// requests.
//
// Backed by store.Store (in-memory or Redis/Dragonfly), so nonce uniqueness
// holds across replicas when a shared backend is configured. With the
// in-memory store, uniqueness is per-process — acceptable when running a
// single replica.
type ReplayGuard struct {
	store    store.Store
	window   time.Duration
	nonceTTL time.Duration
	prefix   string

	// now is the clock source, injectable so tests can pin time.
	now func() time.Time
}

// NewReplayGuard returns a ReplayGuard with the given freshness window.
// The nonce cache TTL is 2×window so a captured request cannot be replayed
// at the edge of expiry.
//
// prefix is prepended to every nonce-cache key. Pass the same prefix used by
// the rest of the brain's store keys so muthur tenants share one keyspace
// convention.
func NewReplayGuard(s store.Store, window time.Duration, prefix string) *ReplayGuard {
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &ReplayGuard{
		store:    s,
		window:   window,
		nonceTTL: 2 * window,
		prefix:   prefix,
		now:      time.Now,
	}
}

// Verify extracts the timestamp + nonce headers from r, validates them, and
// records the nonce as seen. Returns nil iff the request is fresh and the
// nonce was previously unused for this identity.
//
// Identity scopes the nonce cache: a malicious tenant cannot pre-burn nonces
// for another tenant since the cache key embeds the caller's identity.
func (g *ReplayGuard) Verify(ctx context.Context, id *Identity, r *http.Request) error {
	if id == nil {
		// Defense in depth: middleware should reject before we get here.
		return ErrNoIdentity
	}

	tsHeader := r.Header.Get(HeaderTimestamp)
	if tsHeader == "" {
		return ErrReplayMissingTimestamp
	}
	tsUnix, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrReplayBadTimestamp, err)
	}
	reqTime := time.Unix(tsUnix, 0)
	if delta := g.now().Sub(reqTime); delta > g.window || delta < -g.window {
		return fmt.Errorf("%w: %s drift", ErrReplayClockSkew, delta)
	}

	nonce := r.Header.Get(HeaderNonce)
	if nonce == "" {
		return ErrReplayMissingNonce
	}
	if len(nonce) < minNonceHexLen {
		return fmt.Errorf("%w: %d chars (min %d)", ErrReplayBadNonce, len(nonce), minNonceHexLen)
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return fmt.Errorf("%w: %v", ErrReplayBadNonce, err)
	}

	key := g.nonceKey(id, nonce)
	set, err := g.store.SetNX(ctx, key, []byte{1}, g.nonceTTL)
	if err != nil {
		return fmt.Errorf("auth: nonce store: %w", err)
	}
	if !set {
		return ErrReplayNonceReused
	}
	return nil
}

// nonceKey namespaces nonces by identity so two tenants can independently use
// the same random nonce without collision (astronomically unlikely, but the
// per-identity scope also limits the blast radius of a compromised collector).
func (g *ReplayGuard) nonceKey(id *Identity, nonce string) string {
	return g.prefix + "nonce:" + id.String() + ":" + nonce
}
