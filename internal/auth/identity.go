// Package auth provides mTLS-based identity for collector requests.
//
// Identity is authoritative: it comes from the verified client certificate
// presented during the TLS handshake. The payload's self-declared cluster_id
// is later checked against this identity, and any mismatch is rejected.
package auth

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Identity is the authenticated caller derived from a verified client cert.
// It is set on the request context by the mTLS middleware and consumed by
// downstream handlers (ingest, sign-csr).
type Identity struct {
	// TenantID groups one or more clusters that belong to the same vendor
	// customer. Extracted from the SPIFFE URI SAN; empty when only a CN is
	// available.
	TenantID string

	// ClusterID is the unique identifier of the calling collector's cluster.
	// Extracted from the SPIFFE URI SAN (preferred) or the cert CN (fallback).
	ClusterID string

	// NotAfter is the leaf cert expiry. Handlers can surface this to operators
	// (e.g. as a metric) so they can preempt expiry-driven outages.
	NotAfter time.Time

	// SerialNumber is the leaf cert serial as a lowercase hex string. Useful
	// for audit logs: it ties a request back to the exact issued cert.
	SerialNumber string
}

// String returns a short, log-safe representation. Used in structured logs
// where a single field is preferable to a struct dump.
func (i Identity) String() string {
	if i.TenantID == "" {
		return i.ClusterID
	}
	return i.TenantID + "/" + i.ClusterID
}

// ExtractFromCert pulls the identity out of a verified client cert.
//
// Precedence:
//  1. A SPIFFE URI SAN of the shape spiffe://muthur/<tenant>/<cluster>.
//     Both segments are required when this form is present.
//  2. The cert's Common Name, used as ClusterID with no TenantID.
//
// Returns an error only when neither source yields a non-empty ClusterID.
func ExtractFromCert(cert *x509.Certificate) (*Identity, error) {
	if cert == nil {
		return nil, ErrNoIdentity
	}

	id := &Identity{
		NotAfter:     cert.NotAfter,
		SerialNumber: strings.ToLower(cert.SerialNumber.Text(16)),
	}

	for _, u := range cert.URIs {
		if u.Scheme != spiffeScheme {
			continue
		}
		tenant, cluster, err := parseSpiffePath(u)
		if err != nil {
			return nil, err
		}
		id.TenantID = tenant
		id.ClusterID = cluster
		break
	}

	if id.ClusterID == "" {
		id.ClusterID = strings.TrimSpace(cert.Subject.CommonName)
	}

	if id.ClusterID == "" {
		return nil, ErrNoIdentity
	}
	return id, nil
}

const (
	spiffeScheme = "spiffe"
	spiffeHost   = "muthur"
)

// parseSpiffePath expects spiffe://muthur/<tenant>/<cluster> and returns the
// two path segments. Anything else is rejected so callers can distinguish a
// bad URI from a missing one (the latter is silently skipped in ExtractFromCert).
func parseSpiffePath(u *url.URL) (tenant, cluster string, err error) {
	if u.Host != spiffeHost {
		return "", "", fmt.Errorf("%w: host %q (want %q)", ErrMalformedSAN, u.Host, spiffeHost)
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) != 2 || segs[0] == "" || segs[1] == "" {
		return "", "", fmt.Errorf("%w: path %q (want /<tenant>/<cluster>)", ErrMalformedSAN, u.Path)
	}
	return segs[0], segs[1], nil
}

type ctxKey struct{}

// WithContext returns a copy of ctx carrying the given Identity. Used by the
// mTLS middleware after a successful handshake.
func WithContext(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext retrieves the Identity placed by WithContext. The second return
// value is false when no Identity is present — handlers that require auth
// MUST treat this as a hard failure.
func FromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(*Identity)
	return id, ok && id != nil
}

// Errors returned by this package.
var (
	// ErrNoIdentity is returned when a cert yields no usable ClusterID
	// (neither a SPIFFE URI SAN nor a CN), or when no cert is provided.
	ErrNoIdentity = errors.New("auth: no identity in certificate")

	// ErrMalformedSAN is returned when a SPIFFE URI SAN is present but does
	// not match the expected spiffe://muthur/<tenant>/<cluster> shape.
	ErrMalformedSAN = errors.New("auth: malformed SPIFFE SAN")
)
