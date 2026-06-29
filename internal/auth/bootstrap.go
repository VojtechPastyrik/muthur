package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/store"
)

// Tenant is the per-cluster configuration used by the bootstrap path.
// Loaded from the brain's config file (vendor-managed via GitOps). The
// BootstrapTokenHash is the SHA-256 hex of the one-time token shared
// out-of-band with the client at onboarding.
type Tenant struct {
	ClusterID          string        `yaml:"clusterId" json:"clusterId"`
	TenantID           string        `yaml:"tenantId" json:"tenantId"`
	BootstrapTokenHash string        `yaml:"bootstrapTokenHash" json:"bootstrapTokenHash"`
	BootstrapExpiresAt time.Time     `yaml:"bootstrapExpiresAt" json:"bootstrapExpiresAt"`
	Revoked            bool          `yaml:"revoked" json:"revoked"`
	CertDuration       time.Duration `yaml:"-" json:"certDuration"`

	// CertDurationStr is the YAML-friendly form ("720h", "30d") since yaml.v3
	// has no native Duration support. Parsed into CertDuration by NewTenants.
	CertDurationStr string `yaml:"certDuration" json:"-"`
}

// Tenants is the lookup-by-clusterID view of the tenants list. The slice
// itself is small (a handful per vendor); a map keeps the hot path O(1).
type Tenants struct {
	byCluster map[string]Tenant
}

// NewTenants builds a Tenants index from the raw slice. Empty or
// duplicate-ClusterID entries are rejected so a misconfigured file is caught
// at startup rather than at first onboarding. The CertDurationStr field is
// parsed into CertDuration here so downstream code never sees the string.
func NewTenants(list []Tenant) (*Tenants, error) {
	idx := make(map[string]Tenant, len(list))
	for _, t := range list {
		if t.ClusterID == "" {
			return nil, errors.New("auth: tenant entry missing clusterId")
		}
		if _, dup := idx[t.ClusterID]; dup {
			return nil, fmt.Errorf("auth: duplicate tenant clusterId %q", t.ClusterID)
		}
		if t.CertDurationStr != "" && t.CertDuration == 0 {
			d, err := time.ParseDuration(t.CertDurationStr)
			if err != nil {
				return nil, fmt.Errorf("auth: tenant %q: parse certDuration %q: %w", t.ClusterID, t.CertDurationStr, err)
			}
			t.CertDuration = d
		}
		idx[t.ClusterID] = t
	}
	return &Tenants{byCluster: idx}, nil
}

// Lookup returns the Tenant for clusterID. ok is false when no such tenant
// is configured; the bootstrap path treats that as Unauthenticated (don't
// disclose which clusterIDs are known).
func (t *Tenants) Lookup(clusterID string) (Tenant, bool) {
	if t == nil {
		return Tenant{}, false
	}
	v, ok := t.byCluster[clusterID]
	return v, ok
}

// Bootstrap-related sentinel errors. The gRPC adapter maps them:
//
//	ErrBootstrapUnauthorized → codes.Unauthenticated
//	ErrBootstrapForbidden    → codes.PermissionDenied
//	ErrBootstrapBadRequest   → codes.InvalidArgument
//	ErrBootstrapInternal     → codes.Internal
var (
	ErrBootstrapBadRequest   = errors.New("auth: bootstrap bad request")
	ErrBootstrapUnauthorized = errors.New("auth: bootstrap unauthorized")
	ErrBootstrapForbidden    = errors.New("auth: bootstrap forbidden")
	ErrBootstrapInternal     = errors.New("auth: bootstrap internal error")
)

// BootstrapInput is the data extracted from the inbound bootstrap RPC. It
// mirrors the proto BootstrapRequest but is decoupled so the auth package
// has no proto dependency.
type BootstrapInput struct {
	ClusterID      string
	BootstrapToken string
	CSRPEM         string
}

// BootstrapResult carries the freshly issued leaf and the CA chain, both PEM.
type BootstrapResult struct {
	CertificatePEM string
	CAPEM          string
}

// BootstrapHandler issues a first leaf certificate to a collector that has
// no prior credentials. The collector presents a one-time bootstrap token
// out-of-band (delivered via SOPS-encrypted secret in its GitOps repo) and
// a CSR carrying its freshly generated public key. The handler:
//
//  1. Validates the tenant exists, is not revoked, and bootstrap window
//     hasn't expired.
//  2. Constant-time compares SHA-256(token) against the tenant's stored hash.
//  3. Atomically marks the token used in the shared store. The first request
//     wins; concurrent duplicates and replays after success both fail.
//  4. Signs the CSR with the vendor intermediate, binding the authoritative
//     tenant identity (NOT what the CSR claims).
//  5. Returns the leaf + CA chain so the collector can install it and
//     immediately switch to mTLS for /ingest and /sign-csr.
type BootstrapHandler struct {
	tenants TenantsProvider
	signer  *Signer
	store   store.Store
	prefix  string
	logger  *zap.Logger

	// now is the clock source, swappable for tests.
	now func() time.Time

	mu sync.Mutex // serialises in-process bootstrap attempts; SetNX makes it correct, this just reduces log spam under contention
}

// NewBootstrapHandler takes a TenantsProvider so a hot-reload of the tenants
// file (e.g. adding a new tenant, flipping `revoked: true`) is picked up
// without a brain restart. Pass StaticTenants{T: ...} to keep the old
// fixed-snapshot behaviour in tests.
func NewBootstrapHandler(tenants TenantsProvider, signer *Signer, st store.Store, storePrefix string, logger *zap.Logger) *BootstrapHandler {
	return &BootstrapHandler{
		tenants: tenants,
		signer:  signer,
		store:   st,
		prefix:  storePrefix,
		logger:  logger,
		now:     time.Now,
	}
}

// Issue validates the request, claims the one-time bootstrap token atomically,
// and returns a freshly minted leaf + CA chain. The error is one of the
// sentinel ErrBootstrap* variants; the gRPC adapter maps them to status codes.
func (h *BootstrapHandler) Issue(ctx context.Context, in BootstrapInput) (*BootstrapResult, error) {
	if in.ClusterID == "" || in.BootstrapToken == "" || in.CSRPEM == "" {
		return nil, ErrBootstrapBadRequest
	}

	tenants := h.tenants.Current()
	if tenants == nil {
		return nil, ErrBootstrapInternal
	}
	tenant, ok := tenants.Lookup(in.ClusterID)
	if !ok {
		h.logger.Warn("bootstrap for unknown cluster", zap.String("cluster_id", in.ClusterID))
		return nil, ErrBootstrapUnauthorized
	}
	if tenant.Revoked {
		h.logger.Warn("bootstrap for revoked tenant", zap.String("cluster_id", in.ClusterID))
		return nil, ErrBootstrapUnauthorized
	}
	if !tenant.BootstrapExpiresAt.IsZero() && h.now().After(tenant.BootstrapExpiresAt) {
		h.logger.Warn("bootstrap token expired", zap.String("cluster_id", in.ClusterID))
		return nil, ErrBootstrapUnauthorized
	}

	wantHash := strings.TrimPrefix(strings.ToLower(tenant.BootstrapTokenHash), "sha256:")
	gotSum := sha256.Sum256([]byte(in.BootstrapToken))
	gotHash := hex.EncodeToString(gotSum[:])
	if subtle.ConstantTimeCompare([]byte(wantHash), []byte(gotHash)) != 1 {
		h.logger.Warn("bootstrap token mismatch", zap.String("cluster_id", in.ClusterID))
		return nil, ErrBootstrapUnauthorized
	}

	// Single-use enforcement. The marker key lives for the remainder of the
	// bootstrap window (or 24h if no expiry set) so a token cannot be reused
	// even after this process restarts when the store is shared.
	usedKey := h.prefix + "bootstrap:used:" + in.ClusterID
	ttl := 24 * time.Hour
	if !tenant.BootstrapExpiresAt.IsZero() {
		if d := time.Until(tenant.BootstrapExpiresAt); d > ttl {
			ttl = d
		}
	}
	h.mu.Lock()
	set, err := h.store.SetNX(ctx, usedKey, []byte{1}, ttl)
	h.mu.Unlock()
	if err != nil {
		h.logger.Error("bootstrap store SetNX failed", zap.Error(err))
		return nil, fmt.Errorf("%w: %v", ErrBootstrapInternal, err)
	}
	if !set {
		h.logger.Warn("bootstrap token already used", zap.String("cluster_id", in.ClusterID))
		return nil, ErrBootstrapUnauthorized
	}

	certPEM, err := h.signer.Sign(
		[]byte(in.CSRPEM),
		Identity{TenantID: tenant.TenantID, ClusterID: tenant.ClusterID},
		tenant.CertDuration,
	)
	if err != nil {
		// Roll back the used marker so a transient signing failure doesn't
		// burn the only bootstrap token the collector has.
		_ = h.store.Delete(context.Background(), usedKey)
		h.logger.Error("bootstrap CSR signing failed",
			zap.Error(err),
			zap.String("cluster_id", in.ClusterID),
		)
		return nil, fmt.Errorf("%w: %v", ErrBootstrapBadRequest, err)
	}

	h.logger.Info("bootstrap issued",
		zap.String("cluster_id", in.ClusterID),
		zap.String("tenant_id", tenant.TenantID),
		zap.Duration("cert_duration", tenant.CertDuration),
	)

	return &BootstrapResult{
		CertificatePEM: string(certPEM),
		CAPEM:          string(h.signer.CACertPEM()),
	}, nil
}
