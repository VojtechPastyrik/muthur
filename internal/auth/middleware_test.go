package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestMiddleware_RejectsRequestWithoutTLS(t *testing.T) {
	mw := Middleware(zaptest.NewLogger(t))
	called := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if called {
		t.Error("next handler was invoked despite missing TLS state")
	}
}

func TestMiddleware_RejectsTLSWithoutClientCert(t *testing.T) {
	mw := Middleware(zaptest.NewLogger(t))
	called := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	req.TLS = &tls.ConnectionState{} // TLS terminated but no client cert
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if called {
		t.Error("next handler was invoked despite missing client cert")
	}
}

func TestMiddleware_RejectsCertWithoutIdentity(t *testing.T) {
	cert := newTestCert(t, "", "") // empty CN, no SAN ⇒ ExtractFromCert errors
	mw := Middleware(zaptest.NewLogger(t))
	called := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if called {
		t.Error("next handler was invoked for a cert without identity")
	}
}

func TestMiddleware_PropagatesIdentity(t *testing.T) {
	cert := newTestCert(t, "cn-fallback", "spiffe://muthur/acme/cluster-prod")

	mw := Middleware(zaptest.NewLogger(t))
	var got *Identity
	var ok bool
	h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = FromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if !ok {
		t.Fatal("identity not propagated to next handler")
	}
	if got.TenantID != "acme" || got.ClusterID != "cluster-prod" {
		t.Errorf("identity = %+v, want acme/cluster-prod", got)
	}
}

func TestMiddleware_EndToEndOverTLS(t *testing.T) {
	// Full integration test: real TLS handshake through httptest, real cert
	// verification by the Go TLS stack, then this middleware extracts the
	// identity. Guards against subtle wiring bugs that pure unit tests miss.
	caCert, caKey := makeCA(t)
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	serverCert := makeLeaf(t, caCert, caKey, "muthur-server", "", false)
	clientCert := makeLeaf(t, caCert, caKey, "client-cn", "spiffe://muthur/t1/c1", true)

	mw := Middleware(zaptest.NewLogger(t))
	var seen *Identity
	h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
	}))

	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}
	srv.StartTLS()
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caPool,
			},
		},
	}
	resp, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if seen == nil {
		t.Fatal("identity not seen by handler")
	}
	if seen.TenantID != "t1" || seen.ClusterID != "c1" {
		t.Errorf("identity = %+v, want t1/c1", seen)
	}
}

// makeCA returns a usable self-signed CA cert and its private key.
func makeCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MUTHUR Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return cert, priv
}

// makeLeaf issues a cert signed by ca with the given CN and optional SPIFFE URI.
// The client flag toggles ExtKeyUsage between server and client auth.
func makeLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn, spiffeURI string, client bool) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if spiffeURI != "" {
		u, err := url.Parse(spiffeURI)
		if err != nil {
			t.Fatalf("parse spiffe uri: %v", err)
		}
		tpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.Raw},
		PrivateKey:  priv,
		Leaf:        mustParse(t, der),
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}
