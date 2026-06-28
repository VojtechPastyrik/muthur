package auth

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

// Renew-related sentinel errors. The gRPC adapter maps them:
//
//	ErrRenewBadRequest   → codes.InvalidArgument
//	ErrRenewForbidden    → codes.PermissionDenied
var (
	ErrRenewBadRequest = errors.New("auth: renew bad request")
	ErrRenewForbidden  = errors.New("auth: renew forbidden")
)

// RenewInput is the data extracted from the inbound SignCSR RPC. ClusterID is
// intentionally absent: the identity is authoritative from the cert the
// caller is already using on this TLS connection.
type RenewInput struct {
	CSRPEM string
}

// RenewResult mirrors BootstrapResult so collector code can share the
// unmarshal path. The CA is included on every renewal so a collector that
// lost it can re-derive the chain without a separate fetch.
type RenewResult struct {
	CertificatePEM string
	CAPEM          string
}

// RenewHandler signs renewal CSRs for collectors that already hold a valid
// leaf cert. Authentication is the existing mTLS handshake — Identity is
// pulled from the context by the upstream auth interceptor. The CSR
// contributes only the public key; identity is authoritative from the cert.
//
// This is the day-2 path: every ~7 days before expiry the collector mints a
// fresh keypair, sends a CSR, the brain returns the signed leaf, and the
// collector swaps it in via fsnotify without restarting.
type RenewHandler struct {
	tenants *Tenants
	signer  *Signer
	logger  *zap.Logger
}

func NewRenewHandler(tenants *Tenants, signer *Signer, logger *zap.Logger) *RenewHandler {
	return &RenewHandler{tenants: tenants, signer: signer, logger: logger}
}

// Issue signs the renewal CSR using the identity carried in ctx. Replay
// verification is handled by the surrounding interceptor; reaching Issue
// implies the request was fresh.
func (h *RenewHandler) Issue(ctx context.Context, in RenewInput) (*RenewResult, error) {
	id, ok := FromContext(ctx)
	if !ok {
		// Reaching here without Identity means the route was mounted outside
		// the auth interceptor — wiring bug, fail closed.
		h.logger.Warn("sign-csr reached without identity — interceptor not mounted?")
		return nil, ErrNoIdentity
	}

	// If the tenant was revoked since the existing cert was issued, refuse
	// to renew. Existing cert keeps working until expiry — operators who
	// want immediate cutoff also drop /ingest by the same identity via the
	// deny-list path (future commit).
	if tenant, found := h.tenants.Lookup(id.ClusterID); found && tenant.Revoked {
		h.logger.Warn("sign-csr for revoked tenant", zap.String("identity", id.String()))
		return nil, ErrRenewForbidden
	}

	if in.CSRPEM == "" {
		return nil, ErrRenewBadRequest
	}

	// Use the tenant's configured cert duration when available; Signer
	// clamps to MaxLeafDuration so a bogus tenant config can't extend
	// validity beyond the global ceiling.
	duration := h.signer.MaxLeafDuration
	if tenant, found := h.tenants.Lookup(id.ClusterID); found && tenant.CertDuration > 0 {
		duration = tenant.CertDuration
	}

	certPEM, err := h.signer.Sign([]byte(in.CSRPEM), *id, duration)
	if err != nil {
		h.logger.Warn("sign-csr signing failed",
			zap.Error(err),
			zap.String("identity", id.String()),
		)
		return nil, fmt.Errorf("%w: %v", ErrRenewBadRequest, err)
	}

	h.logger.Info("sign-csr issued",
		zap.String("identity", id.String()),
		zap.Duration("duration", duration),
	)

	return &RenewResult{
		CertificatePEM: string(certPEM),
		CAPEM:          string(h.signer.CACertPEM()),
	}, nil
}
