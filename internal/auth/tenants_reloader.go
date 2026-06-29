package auth

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// TenantsProvider returns the current Tenants snapshot. Consumers (interceptors,
// bootstrap/renew handlers) call Current() per request so a Tenants reload is
// picked up without restarting the brain — flipping `revoked: true` in the
// config file then takes effect within one stat poll, instead of waiting for
// the next pod restart.
//
// Implemented by both TenantsReloader (production, watches a file) and a
// static *Tenants wrapper (tests, or deployments where the config never
// changes at runtime).
type TenantsProvider interface {
	Current() *Tenants
}

// StaticTenants wraps a fixed *Tenants as a TenantsProvider. Use in tests and
// in deployments that prefer restart-based reloads.
type StaticTenants struct{ T *Tenants }

func (s StaticTenants) Current() *Tenants { return s.T }

// tenantsFileShape is the minimal slice of the brain config file the reloader
// has to parse. Kept separate from appconfig.FileConfig to avoid an import
// cycle (appconfig depends on auth, not the other way round). The yaml tag
// must match what appconfig exposes.
type tenantsFileShape struct {
	Tenants []Tenant `yaml:"tenants"`
}

// TenantsReloader hot-reloads the tenants list from a YAML file on disk. It
// mirrors certReloader's design: stat-on-read using file mtime, no fsnotify
// dependency, atomic pointer swap so reads stay lock-free in the happy path.
// A failed parse keeps the previous snapshot serving — a cert-manager-style
// mid-write torn read never wipes the authorisation list.
type TenantsReloader struct {
	path       string
	logger     *zap.Logger
	cached     atomic.Pointer[tenantsState]
	pollEvery  time.Duration
	stopCh     chan struct{}
	stoppedCh  chan struct{}
}

type tenantsState struct {
	tenants *Tenants
	mtime   time.Time
}

// NewTenantsReloader loads the file once (failing fast on a missing/bad file
// so misconfiguration surfaces at startup) and returns a reloader ready to
// poll. Call Start to begin the background watch; Stop to shut it down.
// pollEvery <= 0 falls back to 5s — short enough that a revoke takes effect
// well before a typical incident-response cycle, long enough that statting
// a ConfigMap-mounted file is not a hot loop.
func NewTenantsReloader(path string, pollEvery time.Duration, logger *zap.Logger) (*TenantsReloader, error) {
	if pollEvery <= 0 {
		pollEvery = 5 * time.Second
	}
	r := &TenantsReloader{
		path:      path,
		logger:    logger,
		pollEvery: pollEvery,
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
	}
	if _, err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Current returns the active Tenants snapshot. Safe to call concurrently.
func (r *TenantsReloader) Current() *Tenants {
	if s := r.cached.Load(); s != nil {
		return s.tenants
	}
	return nil
}

// Start begins polling the file for mtime changes. Spawns one goroutine; Stop
// terminates it.
func (r *TenantsReloader) Start() {
	go r.loop()
}

// Stop signals the poller to exit and blocks until it does.
func (r *TenantsReloader) Stop() {
	close(r.stopCh)
	<-r.stoppedCh
}

func (r *TenantsReloader) loop() {
	defer close(r.stoppedCh)
	t := time.NewTicker(r.pollEvery)
	defer t.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-t.C:
			if changed, err := r.reload(); err != nil {
				r.logger.Warn("tenants reload failed; serving previous snapshot",
					zap.String("path", r.path),
					zap.Error(err),
				)
			} else if changed {
				cur := r.Current()
				r.logger.Info("tenants reloaded",
					zap.String("path", r.path),
					zap.Int("count", cur.Len()),
				)
			}
		}
	}
}

// reload re-reads the file when its mtime advances past the cached value.
// Returns (changed, err). A torn read / bad YAML is reported and the
// previous snapshot is preserved.
func (r *TenantsReloader) reload() (bool, error) {
	info, err := os.Stat(r.path)
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", r.path, err)
	}
	if cached := r.cached.Load(); cached != nil && !info.ModTime().After(cached.mtime) {
		return false, nil
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", r.path, err)
	}
	var shape tenantsFileShape
	if err := yaml.Unmarshal(data, &shape); err != nil {
		return false, fmt.Errorf("parse %s: %w", r.path, err)
	}
	t, err := NewTenants(shape.Tenants)
	if err != nil {
		return false, fmt.Errorf("build tenants: %w", err)
	}
	r.cached.Store(&tenantsState{tenants: t, mtime: info.ModTime()})
	return true, nil
}

// Len reports the number of configured tenants. Used by the reloader's log
// line so an operator can sanity-check a hot-reload didn't shrink the list
// to zero by accident.
func (t *Tenants) Len() int { return len(t.byCluster) }
