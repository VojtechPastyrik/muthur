package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func newRenewHandler(t *testing.T, tenants ...Tenant) *RenewHandler {
	t.Helper()
	idx, err := NewTenants(tenants)
	if err != nil {
		t.Fatalf("NewTenants: %v", err)
	}
	return NewRenewHandler(idx, newTestSigner(t), zaptest.NewLogger(t))
}

func ctxWith(id *Identity) context.Context {
	return WithContext(context.Background(), id)
}

func TestRenew_HappyPath(t *testing.T) {
	h := newRenewHandler(t, Tenant{
		ClusterID:    "cluster-a",
		TenantID:     "acme",
		CertDuration: time.Hour,
	})
	csrPEM, _ := makeCSR(t, "ignored-cn")
	ctx := ctxWith(&Identity{TenantID: "acme", ClusterID: "cluster-a"})

	res, err := h.Issue(ctx, RenewInput{CSRPEM: string(csrPEM)})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	leaf := parseLeafPEM(t, []byte(res.CertificatePEM))
	id, err := ExtractFromCert(leaf)
	if err != nil {
		t.Fatalf("ExtractFromCert: %v", err)
	}
	if id.TenantID != "acme" || id.ClusterID != "cluster-a" {
		t.Errorf("identity = %+v, want acme/cluster-a", id)
	}
}

func TestRenew_RejectsMissingIdentity(t *testing.T) {
	h := newRenewHandler(t)
	csrPEM, _ := makeCSR(t, "x")
	_, err := h.Issue(context.Background(), RenewInput{CSRPEM: string(csrPEM)})
	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("err = %v, want ErrNoIdentity", err)
	}
}

func TestRenew_RejectsRevokedTenant(t *testing.T) {
	h := newRenewHandler(t, Tenant{
		ClusterID: "cluster-a", TenantID: "acme", Revoked: true,
	})
	csrPEM, _ := makeCSR(t, "x")
	ctx := ctxWith(&Identity{TenantID: "acme", ClusterID: "cluster-a"})

	_, err := h.Issue(ctx, RenewInput{CSRPEM: string(csrPEM)})
	if !errors.Is(err, ErrRenewForbidden) {
		t.Errorf("err = %v, want ErrRenewForbidden", err)
	}
}

func TestRenew_BadCSR(t *testing.T) {
	h := newRenewHandler(t, Tenant{ClusterID: "cluster-a", TenantID: "acme", CertDuration: time.Hour})
	ctx := ctxWith(&Identity{TenantID: "acme", ClusterID: "cluster-a"})

	_, err := h.Issue(ctx, RenewInput{CSRPEM: "not a csr"})
	if !errors.Is(err, ErrRenewBadRequest) {
		t.Errorf("err = %v, want ErrRenewBadRequest", err)
	}
}

func TestRenew_RejectsEmptyCSR(t *testing.T) {
	h := newRenewHandler(t, Tenant{ClusterID: "cluster-a", CertDuration: time.Hour})
	ctx := ctxWith(&Identity{ClusterID: "cluster-a"})

	_, err := h.Issue(ctx, RenewInput{CSRPEM: ""})
	if !errors.Is(err, ErrRenewBadRequest) {
		t.Errorf("err = %v, want ErrRenewBadRequest", err)
	}
}

func TestRenew_FallsBackToMaxLeafDurationWhenTenantMissing(t *testing.T) {
	// No tenant configured for this clusterID. Signer still mints a cert
	// because the caller already holds a valid mTLS cert; the brain's
	// tenants list is the deny/duration source, not the auth source. This
	// matches the deployment reality where tenants config may temporarily
	// drift behind cert rotations.
	h := newRenewHandler(t)
	csrPEM, _ := makeCSR(t, "x")
	ctx := ctxWith(&Identity{ClusterID: "ghost"})

	if _, err := h.Issue(ctx, RenewInput{CSRPEM: string(csrPEM)}); err != nil {
		t.Errorf("Issue err = %v, want nil (fall through to MaxLeafDuration)", err)
	}
}
