package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"go.uber.org/zap"
)

// RenewHandler signs renewal CSRs for collectors that already hold a valid
// leaf cert. Authentication is the existing mTLS handshake — Identity is
// pulled from the request context by the upstream Middleware. The CSR
// contributes only the public key; identity is authoritative from the cert.
//
// This is the day-2 path: every ~7 days before expiry the collector mints a
// fresh keypair, sends a CSR, the brain returns the signed leaf, and the
// collector swaps it in via fsnotify without restarting.
type RenewHandler struct {
	tenants *Tenants
	signer  *Signer
	replay  *ReplayGuard
	logger  *zap.Logger
}

func NewRenewHandler(tenants *Tenants, signer *Signer, replay *ReplayGuard, logger *zap.Logger) *RenewHandler {
	return &RenewHandler{tenants: tenants, signer: signer, replay: replay, logger: logger}
}

// RenewRequest carries the renewal CSR. ClusterID is intentionally absent:
// the identity is authoritative from the cert the caller is already using
// on this TLS connection, and a request body field would only invite
// confusion or smuggling attempts.
type RenewRequest struct {
	CSR string `json:"csr"` // PEM
}

// RenewResponse is the same shape as BootstrapResponse so collector code can
// share the unmarshal path. The CA is included on every renewal so a
// collector that lost it can re-derive the chain without a separate fetch.
type RenewResponse struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
}

func (h *RenewHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, ok := FromContext(r.Context())
	if !ok {
		// Reaching here without Identity means the route was mounted outside
		// the auth Middleware — wiring bug, fail closed.
		h.logger.Warn("sign-csr reached without identity — middleware not mounted?")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.replay.Verify(r.Context(), id, r); err != nil {
		status := http.StatusUnauthorized
		switch {
		case errors.Is(err, ErrReplayMissingTimestamp),
			errors.Is(err, ErrReplayBadTimestamp),
			errors.Is(err, ErrReplayMissingNonce),
			errors.Is(err, ErrReplayBadNonce):
			status = http.StatusBadRequest
		}
		h.logger.Warn("sign-csr replay check failed",
			zap.Error(err),
			zap.String("identity", id.String()),
		)
		http.Error(w, http.StatusText(status), status)
		return
	}

	// If the tenant was revoked since the existing cert was issued, refuse
	// to renew. Existing cert keeps working until expiry — operators who
	// want immediate cutoff also drop /ingest by the same identity via the
	// deny-list path (future commit).
	if tenant, found := h.tenants.Lookup(id.ClusterID); found && tenant.Revoked {
		h.logger.Warn("sign-csr for revoked tenant",
			zap.String("identity", id.String()),
		)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var req RenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CSR == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Use the tenant's configured cert duration when available; Signer
	// clamps to MaxLeafDuration so a bogus tenant config can't extend
	// validity beyond the global ceiling.
	duration := h.signer.MaxLeafDuration
	if tenant, found := h.tenants.Lookup(id.ClusterID); found && tenant.CertDuration > 0 {
		duration = tenant.CertDuration
	}

	certPEM, err := h.signer.Sign([]byte(req.CSR), *id, duration)
	if err != nil {
		h.logger.Warn("sign-csr signing failed",
			zap.Error(err),
			zap.String("identity", id.String()),
		)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	h.logger.Info("sign-csr issued",
		zap.String("identity", id.String()),
		zap.Duration("duration", duration),
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(RenewResponse{
		Certificate: string(certPEM),
		CA:          string(h.signer.CACertPEM()),
	})
}
