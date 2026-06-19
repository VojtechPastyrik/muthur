package store

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Memory is an in-process Store. It is the zero-dependency default used when no
// Redis URL is configured. State is lost on restart and not shared across
// replicas — acceptable for single-instance deployments.
type Memory struct {
	mu    sync.RWMutex
	items map[string]memItem
	stop  chan struct{}
}

type memItem struct {
	val       []byte
	expiresAt time.Time // zero means no expiry
}

func (i memItem) expired(now time.Time) bool {
	return !i.expiresAt.IsZero() && now.After(i.expiresAt)
}

// NewMemory returns an in-memory store with a background janitor that evicts
// expired entries every minute.
func NewMemory() *Memory {
	m := &Memory{
		items: make(map[string]memItem),
		stop:  make(chan struct{}),
	}
	go m.janitor()
	return m
}

func (m *Memory) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.RLock()
	it, ok := m.items[key]
	m.mu.RUnlock()
	if !ok || it.expired(time.Now()) {
		return nil, false, nil
	}
	// Return a copy so callers can't mutate stored bytes.
	out := make([]byte, len(it.val))
	copy(out, it.val)
	return out, true, nil
}

func (m *Memory) Set(_ context.Context, key string, val []byte, ttl time.Duration) error {
	m.mu.Lock()
	m.items[key] = memItem{val: cloneBytes(val), expiresAt: expiry(ttl)}
	m.mu.Unlock()
	return nil
}

func (m *Memory) SetNX(_ context.Context, key string, val []byte, ttl time.Duration) (bool, error) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if it, ok := m.items[key]; ok && !it.expired(now) {
		return false, nil
	}
	m.items[key] = memItem{val: cloneBytes(val), expiresAt: expiry(ttl)}
	return true, nil
}

func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	delete(m.items, key)
	m.mu.Unlock()
	return nil
}

func (m *Memory) ListByPrefix(_ context.Context, prefix string) ([][]byte, error) {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out [][]byte
	for k, it := range m.items {
		if it.expired(now) || !strings.HasPrefix(k, prefix) {
			continue
		}
		out = append(out, cloneBytes(it.val))
	}
	return out, nil
}

func (m *Memory) Kind() string { return "memory" }

func (m *Memory) Close() error {
	close(m.stop)
	return nil
}

func (m *Memory) janitor() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			now := time.Now()
			m.mu.Lock()
			for k, it := range m.items {
				if it.expired(now) {
					delete(m.items, k)
				}
			}
			m.mu.Unlock()
		}
	}
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func expiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return time.Now().Add(ttl)
}
