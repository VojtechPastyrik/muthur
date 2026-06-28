package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/VojtechPastyrik/muthur/internal/store"
)

func newRenewHandler(t *testing.T, tenants ...Tenant) *RenewHandler {
	t.Helper()
	idx, err := NewTenants(tenants)
	if err != nil {
		t.Fatalf("NewTenants: %v", err)
	}
	st := store.NewMemory()
	return NewRenewHandler(idx, newTestSigner(t), NewReplayGuard(st, 5*time.Minute, "muthur:"), zaptest.NewLogger(t))
}

// authedRenewRequest builds a POST /sign-csr with Identity in ctx, fresh
// replay headers, and the given JSON body.
func authedRenewRequest(t *testing.T, id *Identity, body RenewRequest) *http.Request {
	t.Helper()
	buf, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(buf))
	r.Header.Set(HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	r.Header.Set(HeaderNonce, hex.EncodeToString(nonce[:]))
	return r.WithContext(WithContext(r.Context(), id))
}

func TestRenew_HappyPath(t *testing.T) {
	h := newRenewHandler(t, Tenant{
		ClusterID:    "cluster-a",
		TenantID:     "acme",
		CertDuration: time.Hour,
	})
	csrPEM, _ := makeCSR(t, "ignored-cn")
	req := authedRenewRequest(t, &Identity{TenantID: "acme", ClusterID: "cluster-a"}, RenewRequest{CSR: string(csrPEM)})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	var resp RenewResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	leaf := parseLeafPEM(t, []byte(resp.Certificate))
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
	body, _ := json.Marshal(RenewRequest{CSR: string(csrPEM)})
	req := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(body))
	// No Identity in context.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestRenew_RejectsRevokedTenant(t *testing.T) {
	h := newRenewHandler(t, Tenant{
		ClusterID: "cluster-a", TenantID: "acme", Revoked: true,
	})
	csrPEM, _ := makeCSR(t, "x")
	req := authedRenewRequest(t, &Identity{TenantID: "acme", ClusterID: "cluster-a"}, RenewRequest{CSR: string(csrPEM)})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestRenew_RejectsReplayedNonce(t *testing.T) {
	h := newRenewHandler(t, Tenant{ClusterID: "cluster-a", TenantID: "acme", CertDuration: time.Hour})
	csrPEM, _ := makeCSR(t, "x")
	id := &Identity{TenantID: "acme", ClusterID: "cluster-a"}

	// Pin nonce so two requests share it.
	pinned := "abcdef0123456789abcdef0123456789"
	build := func() *http.Request {
		body, _ := json.Marshal(RenewRequest{CSR: string(csrPEM)})
		r := httptest.NewRequest(http.MethodPost, "/sign-csr", bytes.NewReader(body))
		r.Header.Set(HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
		r.Header.Set(HeaderNonce, pinned)
		return r.WithContext(WithContext(r.Context(), id))
	}

	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, build())
	if rr1.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", rr1.Code)
	}
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, build())
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("replay status = %d, want 401", rr2.Code)
	}
}

func TestRenew_BadCSR(t *testing.T) {
	h := newRenewHandler(t, Tenant{ClusterID: "cluster-a", TenantID: "acme", CertDuration: time.Hour})
	req := authedRenewRequest(t, &Identity{TenantID: "acme", ClusterID: "cluster-a"}, RenewRequest{CSR: "not a csr"})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestRenew_RejectsNonPOST(t *testing.T) {
	h := newRenewHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/sign-csr", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestRenew_RejectsEmptyCSR(t *testing.T) {
	h := newRenewHandler(t, Tenant{ClusterID: "cluster-a", CertDuration: time.Hour})
	req := authedRenewRequest(t, &Identity{ClusterID: "cluster-a"}, RenewRequest{CSR: ""})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
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
	req := authedRenewRequest(t, &Identity{ClusterID: "ghost"}, RenewRequest{CSR: string(csrPEM)})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (fall through to MaxLeafDuration)", rr.Code)
	}
}
