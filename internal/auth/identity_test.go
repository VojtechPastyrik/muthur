package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestExtractFromCert_SpiffeSAN(t *testing.T) {
	cert := newTestCert(t, "fallback-cn", "spiffe://muthur/acme/cluster-prod")

	id, err := ExtractFromCert(cert)
	if err != nil {
		t.Fatalf("ExtractFromCert: %v", err)
	}
	if got, want := id.TenantID, "acme"; got != want {
		t.Errorf("TenantID = %q, want %q", got, want)
	}
	if got, want := id.ClusterID, "cluster-prod"; got != want {
		t.Errorf("ClusterID = %q, want %q", got, want)
	}
	if id.NotAfter.IsZero() {
		t.Error("NotAfter is zero")
	}
	if id.SerialNumber == "" {
		t.Error("SerialNumber is empty")
	}
}

func TestExtractFromCert_CNFallback(t *testing.T) {
	cert := newTestCert(t, "cluster-home", "")

	id, err := ExtractFromCert(cert)
	if err != nil {
		t.Fatalf("ExtractFromCert: %v", err)
	}
	if id.TenantID != "" {
		t.Errorf("TenantID = %q, want empty (CN-only cert)", id.TenantID)
	}
	if got, want := id.ClusterID, "cluster-home"; got != want {
		t.Errorf("ClusterID = %q, want %q", got, want)
	}
}

func TestExtractFromCert_SpiffeWinsOverCN(t *testing.T) {
	cert := newTestCert(t, "cn-should-lose", "spiffe://muthur/t/c")

	id, err := ExtractFromCert(cert)
	if err != nil {
		t.Fatalf("ExtractFromCert: %v", err)
	}
	if got, want := id.ClusterID, "c"; got != want {
		t.Errorf("ClusterID = %q, want %q (SPIFFE must win)", got, want)
	}
}

func TestExtractFromCert_NoCert(t *testing.T) {
	_, err := ExtractFromCert(nil)
	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("err = %v, want ErrNoIdentity", err)
	}
}

func TestExtractFromCert_EmptyCN_NoSAN(t *testing.T) {
	cert := newTestCert(t, "", "")

	_, err := ExtractFromCert(cert)
	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("err = %v, want ErrNoIdentity", err)
	}
}

func TestExtractFromCert_MalformedSpiffeHost(t *testing.T) {
	cert := newTestCert(t, "", "spiffe://other-host/t/c")

	_, err := ExtractFromCert(cert)
	if !errors.Is(err, ErrMalformedSAN) {
		t.Errorf("err = %v, want ErrMalformedSAN", err)
	}
}

func TestExtractFromCert_MalformedSpiffePath(t *testing.T) {
	cases := []string{
		"spiffe://muthur/onlytenant",
		"spiffe://muthur/t/c/extra",
		"spiffe://muthur//",
	}
	for _, uri := range cases {
		t.Run(uri, func(t *testing.T) {
			cert := newTestCert(t, "", uri)
			_, err := ExtractFromCert(cert)
			if !errors.Is(err, ErrMalformedSAN) {
				t.Errorf("err = %v, want ErrMalformedSAN", err)
			}
		})
	}
}

func TestExtractFromCert_NonSpiffeURIIsIgnored(t *testing.T) {
	// A non-SPIFFE URI SAN (e.g. an HTTPS DNS-as-URI) must not block CN fallback.
	cert := newTestCert(t, "cluster-x", "https://example.com")

	id, err := ExtractFromCert(cert)
	if err != nil {
		t.Fatalf("ExtractFromCert: %v", err)
	}
	if got, want := id.ClusterID, "cluster-x"; got != want {
		t.Errorf("ClusterID = %q, want %q", got, want)
	}
}

func TestIdentityString(t *testing.T) {
	cases := []struct {
		id   Identity
		want string
	}{
		{Identity{ClusterID: "c"}, "c"},
		{Identity{TenantID: "t", ClusterID: "c"}, "t/c"},
	}
	for _, tc := range cases {
		if got := tc.id.String(); got != tc.want {
			t.Errorf("Identity{%+v}.String() = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestContextRoundtrip(t *testing.T) {
	id := &Identity{TenantID: "t", ClusterID: "c"}
	ctx := WithContext(context.Background(), id)

	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext: ok = false")
	}
	if got != id {
		t.Errorf("FromContext returned different pointer")
	}
}

func TestFromContext_Missing(t *testing.T) {
	_, ok := FromContext(context.Background())
	if ok {
		t.Error("FromContext: ok = true for empty context")
	}
}

func TestFromContext_NilIdentity(t *testing.T) {
	// A nil *Identity stored explicitly must report ok=false so callers can
	// rely on the second return value as a "has usable identity" check.
	ctx := WithContext(context.Background(), nil)
	if _, ok := FromContext(ctx); ok {
		t.Error("FromContext: ok = true for nil identity")
	}
}

// newTestCert builds a self-signed cert with the given CN and optional URI SAN.
// Empty cn / uri are simply omitted. The cert is never marshalled to PEM nor
// used for an actual TLS handshake — these tests exercise ExtractFromCert only.
func newTestCert(t *testing.T, cn, uri string) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("parse URI %q: %v", uri, err)
		}
		tpl.URIs = []*url.URL{u}
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
