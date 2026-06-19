// Package store provides a small key/value abstraction with TTL support that
// backs the durable state in muthur-central: dedup windows, the LLM analysis
// cache, semantic-cache vectors, and operator feedback.
//
// Two implementations are provided: an in-memory store (the default, requires
// no external dependency) and a Redis/Dragonfly-backed store (shared across
// replicas and durable across restarts). Selection happens in New based on
// configuration — callers depend only on the Store interface.
package store

import (
	"context"
	"time"
)

// Store is a TTL-aware key/value store. All implementations are safe for
// concurrent use.
type Store interface {
	// Get returns the value for key. ok is false when the key is absent or
	// expired. err is non-nil only on backend failure.
	Get(ctx context.Context, key string) (val []byte, ok bool, err error)

	// Set stores val under key with the given TTL. A ttl of 0 means no
	// expiry.
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error

	// SetNX atomically stores val under key only if key does not already
	// exist, returning true when the value was written. Used for dedup: the
	// first writer wins, concurrent duplicates observe false.
	SetNX(ctx context.Context, key string, val []byte, ttl time.Duration) (set bool, err error)

	// Delete removes key. Deleting a missing key is not an error.
	Delete(ctx context.Context, key string) error

	// ListByPrefix returns the values of all live (non-expired) keys whose
	// name starts with prefix. Used by the semantic cache to scan recent
	// analysis vectors. Order is unspecified.
	ListByPrefix(ctx context.Context, prefix string) ([][]byte, error)

	// Kind reports the backend kind ("memory" or "redis") for logging and
	// metrics.
	Kind() string

	// Close releases any backend resources.
	Close() error
}
