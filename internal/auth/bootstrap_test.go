package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	h := NewBootstrapHandler(idx, newTestSigner(t), st, "muthur:", zaptest.NewLogger(t))
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

	resp := postBootstrap(t, h, BootstrapRequest{
		ClusterID:      "cluster-acme",
		BootstrapToken: token,
		CSR:            string(csrPEM),
	})

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.Code, resp.Body.String())
	}
	var body BootstrapResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Certificate == "" || body.CA == "" {
		t.Errorf("response missing cert or CA: %+v", body)
	}

	// Round-trip the issued cert: the identity must equal the tenant's.
	leaf := parseLeafPEM(t, []byte(body.Certificate))
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

	resp := postBootstrap(t, h, BootstrapRequest{
		ClusterID:      "cluster-ghost",
		BootstrapToken: "anything",
		CSR:            string(csrPEM),
	})
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.Code)
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

	resp := postBootstrap(t, h, BootstrapRequest{
		ClusterID: "cluster-a", BootstrapToken: token, CSR: string(csrPEM),
	})
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.Code)
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

	resp := postBootstrap(t, h, BootstrapRequest{
		ClusterID: "cluster-a", BootstrapToken: token, CSR: string(csrPEM),
	})
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.Code)
	}
}

func TestBootstrap_RejectsWrongToken(t *testing.T) {
	h, _ := newBootstrapHandler(t, Tenant{
		ClusterID:          "cluster-a",
		BootstrapTokenHash: "sha256:" + sha256hex("correct"),
		BootstrapExpiresAt: time.Now().Add(time.Hour),
	})
	csrPEM, _ := makeCSR(t, "x")

	resp := postBootstrap(t, h, BootstrapRequest{
		ClusterID: "cluster-a", BootstrapToken: "wrong", CSR: string(csrPEM),
	})
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.Code)
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

	first := postBootstrap(t, h, BootstrapRequest{
		ClusterID: "cluster-a", BootstrapToken: token, CSR: string(csrPEM),
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}

	// Second attempt with the same token, same CSR, must be rejected.
	second := postBootstrap(t, h, BootstrapRequest{
		ClusterID: "cluster-a", BootstrapToken: token, CSR: string(csrPEM),
	})
	if second.Code != http.StatusUnauthorized {
		t.Errorf("second status = %d, want 401 (single-use enforcement)", second.Code)
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

	bad := postBootstrap(t, h, BootstrapRequest{
		ClusterID: "cluster-a", BootstrapToken: token, CSR: "not a csr",
	})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("bad CSR status = %d, want 400", bad.Code)
	}

	// Retry with a good CSR — must succeed.
	csrPEM, _ := makeCSR(t, "x")
	good := postBootstrap(t, h, BootstrapRequest{
		ClusterID: "cluster-a", BootstrapToken: token, CSR: string(csrPEM),
	})
	if good.Code != http.StatusOK {
		t.Errorf("retry status = %d, want 200 (token must be preserved after bad CSR)", good.Code)
	}
}

func TestBootstrap_RejectsNonPOST(t *testing.T) {
	h, _ := newBootstrapHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/bootstrap-cert", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestBootstrap_RejectsEmptyFields(t *testing.T) {
	h, _ := newBootstrapHandler(t)
	resp := postBootstrap(t, h, BootstrapRequest{})
	if resp.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.Code)
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

func postBootstrap(t *testing.T, h *BootstrapHandler, body BootstrapRequest) *httptest.ResponseRecorder {
	t.Helper()
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/bootstrap-cert", bytes.NewReader(buf))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}
