package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/VojtechPastyrik/muthur/internal/store"
)

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newBootstrapHandler(t *testing.T, tenants ...Tenant) (*BootstrapHandler, store.Store) {
	t.Helper()
	idx, err := NewTenants(tenants)
	if err != nil {
		t.Fatalf("NewTenants: %v", err)
	}
	st := store.NewMemory()
	h := NewBootstrapHandler(StaticTenants{T: idx}, newTestSigner(t), st, "muthur:", zaptest.NewLogger(t))
	return h, st
}

func TestBootstrap_HappyPath(t *testing.T) {
	token := "the-one-time-token"
	h, _ := newBootstrapHandler(t, Tenant{
		ClusterID:          "cluster-acme",
		TenantID:           "acme",
		BootstrapTokenHash: "sha256:" + sha256hex(token),
		BootstrapExpiresAt: time.Now().Add(time.Hour),
		CertDuration:       time.Hour,
	})
	csrPEM, _ := makeCSR(t, "anything")

	res, err := h.Issue(context.Background(), BootstrapInput{
		ClusterID:      "cluster-acme",
		BootstrapToken: token,
		CSRPEM:         string(csrPEM),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res.CertificatePEM == "" || res.CAPEM == "" {
		t.Errorf("response missing cert or CA: %+v", res)
	}

	// Round-trip the issued cert: the identity must equal the tenant's.
	leaf := parseLeafPEM(t, []byte(res.CertificatePEM))
	id, err := ExtractFromCert(leaf)
	if err != nil {
		t.Fatalf("ExtractFromCert: %v", err)
	}
	if id.TenantID != "acme" || id.ClusterID != "cluster-acme" {
		t.Errorf("issued identity = %+v, want acme/cluster-acme", id)
	}
}

func TestBootstrap_RejectsUnknownCluster(t *testing.T) {
	h, _ := newBootstrapHandler(t)
	csrPEM, _ := makeCSR(t, "x")

	_, err := h.Issue(context.Background(), BootstrapInput{
		ClusterID: "cluster-ghost", BootstrapToken: "anything", CSRPEM: string(csrPEM),
	})
	if !errors.Is(err, ErrBootstrapUnauthorized) {
		t.Errorf("err = %v, want ErrBootstrapUnauthorized", err)
	}
}

func TestBootstrap_RejectsRevokedTenant(t *testing.T) {
	token := "tok"
	h, _ := newBootstrapHandler(t, Tenant{
		ClusterID:          "cluster-a",
		BootstrapTokenHash: "sha256:" + sha256hex(token),
		BootstrapExpiresAt: time.Now().Add(time.Hour),
		Revoked:            true,
	})
	csrPEM, _ := makeCSR(t, "x")

	_, err := h.Issue(context.Background(), BootstrapInput{
		ClusterID: "cluster-a", BootstrapToken: token, CSRPEM: string(csrPEM),
	})
	if !errors.Is(err, ErrBootstrapUnauthorized) {
		t.Errorf("err = %v, want ErrBootstrapUnauthorized", err)
	}
}

func TestBootstrap_RejectsExpiredToken(t *testing.T) {
	token := "tok"
	h, _ := newBootstrapHandler(t, Tenant{
		ClusterID:          "cluster-a",
		BootstrapTokenHash: "sha256:" + sha256hex(token),
		BootstrapExpiresAt: time.Now().Add(-time.Hour),
	})
	csrPEM, _ := makeCSR(t, "x")

	_, err := h.Issue(context.Background(), BootstrapInput{
		ClusterID: "cluster-a", BootstrapToken: token, CSRPEM: string(csrPEM),
	})
	if !errors.Is(err, ErrBootstrapUnauthorized) {
		t.Errorf("err = %v, want ErrBootstrapUnauthorized", err)
	}
}

func TestBootstrap_RejectsWrongToken(t *testing.T) {
	h, _ := newBootstrapHandler(t, Tenant{
		ClusterID:          "cluster-a",
		BootstrapTokenHash: "sha256:" + sha256hex("correct"),
		BootstrapExpiresAt: time.Now().Add(time.Hour),
	})
	csrPEM, _ := makeCSR(t, "x")

	_, err := h.Issue(context.Background(), BootstrapInput{
		ClusterID: "cluster-a", BootstrapToken: "wrong", CSRPEM: string(csrPEM),
	})
	if !errors.Is(err, ErrBootstrapUnauthorized) {
		t.Errorf("err = %v, want ErrBootstrapUnauthorized", err)
	}
}

func TestBootstrap_TokenIsSingleUse(t *testing.T) {
	token := "tok"
	h, _ := newBootstrapHandler(t, Tenant{
		ClusterID:          "cluster-a",
		TenantID:           "t",
		BootstrapTokenHash: "sha256:" + sha256hex(token),
		BootstrapExpiresAt: time.Now().Add(time.Hour),
		CertDuration:       time.Hour,
	})
	csrPEM, _ := makeCSR(t, "x")

	if _, err := h.Issue(context.Background(), BootstrapInput{
		ClusterID: "cluster-a", BootstrapToken: token, CSRPEM: string(csrPEM),
	}); err != nil {
		t.Fatalf("first Issue: %v", err)
	}

	// Second attempt with the same token must be rejected.
	_, err := h.Issue(context.Background(), BootstrapInput{
		ClusterID: "cluster-a", BootstrapToken: token, CSRPEM: string(csrPEM),
	})
	if !errors.Is(err, ErrBootstrapUnauthorized) {
		t.Errorf("second Issue err = %v, want ErrBootstrapUnauthorized (single-use)", err)
	}
}

func TestBootstrap_BadCSRPreservesToken(t *testing.T) {
	// If the CSR is malformed, the bootstrap token MUST remain usable so the
	// collector can retry with a fixed CSR — otherwise a typo permanently
	// burns the only one-time credential the client has.
	token := "tok"
	h, _ := newBootstrapHandler(t, Tenant{
		ClusterID:          "cluster-a",
		BootstrapTokenHash: "sha256:" + sha256hex(token),
		BootstrapExpiresAt: time.Now().Add(time.Hour),
		CertDuration:       time.Hour,
	})

	_, err := h.Issue(context.Background(), BootstrapInput{
		ClusterID: "cluster-a", BootstrapToken: token, CSRPEM: "not a csr",
	})
	if !errors.Is(err, ErrBootstrapBadRequest) {
		t.Fatalf("bad CSR err = %v, want ErrBootstrapBadRequest", err)
	}

	// Retry with a good CSR — must succeed.
	csrPEM, _ := makeCSR(t, "x")
	if _, err := h.Issue(context.Background(), BootstrapInput{
		ClusterID: "cluster-a", BootstrapToken: token, CSRPEM: string(csrPEM),
	}); err != nil {
		t.Errorf("retry Issue err = %v, want nil (token must survive bad CSR)", err)
	}
}

func TestBootstrap_RejectsEmptyFields(t *testing.T) {
	h, _ := newBootstrapHandler(t)
	_, err := h.Issue(context.Background(), BootstrapInput{})
	if !errors.Is(err, ErrBootstrapBadRequest) {
		t.Errorf("err = %v, want ErrBootstrapBadRequest", err)
	}
}

func TestNewTenants_RejectsDuplicates(t *testing.T) {
	_, err := NewTenants([]Tenant{{ClusterID: "x"}, {ClusterID: "x"}})
	if err == nil {
		t.Error("NewTenants accepted duplicate clusterId")
	}
}

func TestNewTenants_RejectsEmpty(t *testing.T) {
	_, err := NewTenants([]Tenant{{}})
	if err == nil {
		t.Error("NewTenants accepted empty clusterId")
	}
}
