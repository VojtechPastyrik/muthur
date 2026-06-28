package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSigner_SignProducesValidCertChain(t *testing.T) {
	signer := newTestSigner(t)
	csrPEM, _ := makeCSR(t, "client-claimed-cn")

	got, err := signer.Sign(csrPEM, Identity{TenantID: "acme", ClusterID: "cluster-a"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	leaf := parseLeafPEM(t, got)
	if leaf.Subject.CommonName != "cluster-a" {
		t.Errorf("leaf CN = %q, want cluster-a (authoritative identity)", leaf.Subject.CommonName)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://muthur/acme/cluster-a" {
		t.Errorf("leaf URIs = %v, want [spiffe://muthur/acme/cluster-a]", leaf.URIs)
	}

	// Round-trip: ExtractFromCert against the freshly signed leaf must yield
	// the identity we asked for. Anything else means Sign or Extract drifted.
	id, err := ExtractFromCert(leaf)
	if err != nil {
		t.Fatalf("ExtractFromCert: %v", err)
	}
	if id.TenantID != "acme" || id.ClusterID != "cluster-a" {
		t.Errorf("round-trip identity = %+v, want acme/cluster-a", id)
	}
}

func TestSigner_IgnoresCSRClaimedIdentity(t *testing.T) {
	// The CSR claims a different CN; the signer must overwrite it with the
	// authoritative ClusterID. Otherwise a compromised collector could mint a
	// cert for a different cluster.
	signer := newTestSigner(t)
	csrPEM, _ := makeCSR(t, "i-want-to-be-cluster-z")

	got, err := signer.Sign(csrPEM, Identity{ClusterID: "cluster-a"}, time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	leaf := parseLeafPEM(t, got)
	if leaf.Subject.CommonName != "cluster-a" {
		t.Errorf("CN = %q, want cluster-a (CSR claim must be ignored)", leaf.Subject.CommonName)
	}
}

func TestSigner_RejectsCSRWithBrokenSignature(t *testing.T) {
	signer := newTestSigner(t)
	csrPEM := mangleCSRSignature(t, makeCSRBytes(t, "x"))

	_, err := signer.Sign(csrPEM, Identity{ClusterID: "cluster-a"}, time.Hour)
	if err == nil {
		t.Fatal("Sign accepted CSR with broken signature")
	}
}

func TestSigner_ClampsDurationToMax(t *testing.T) {
	signer := newTestSigner(t)
	signer.MaxLeafDuration = 2 * time.Hour
	csrPEM, _ := makeCSR(t, "x")

	got, err := signer.Sign(csrPEM, Identity{ClusterID: "cluster-a"}, 1000*time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	leaf := parseLeafPEM(t, got)
	if remain := time.Until(leaf.NotAfter); remain > 3*time.Hour {
		t.Errorf("NotAfter = %s from now, want clamped to ~2h", remain)
	}
}

func TestSigner_DefaultsToMaxOnNonPositiveDuration(t *testing.T) {
	signer := newTestSigner(t)
	signer.MaxLeafDuration = 4 * time.Hour
	csrPEM, _ := makeCSR(t, "x")

	got, err := signer.Sign(csrPEM, Identity{ClusterID: "cluster-a"}, 0)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	leaf := parseLeafPEM(t, got)
	if remain := time.Until(leaf.NotAfter); remain < 3*time.Hour {
		t.Errorf("NotAfter = %s from now, want ~4h (default to Max on 0)", remain)
	}
}

func TestNewSignerFromFiles_RoundtripPKCS8(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	writeIntermediate(t, certPath, keyPath)

	signer, err := NewSignerFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewSignerFromFiles: %v", err)
	}
	if signer.caCert == nil || signer.caKey == nil {
		t.Fatal("signer missing cert or key")
	}
	if signer.MaxLeafDuration == 0 {
		t.Error("MaxLeafDuration is zero — production default missing")
	}
}

func TestNewSignerFromFiles_RejectsNonCA(t *testing.T) {
	// A non-CA cert at the intermediate slot must be refused: it cannot
	// validly sign downstream leaves.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "leaf.crt")
	keyPath := filepath.Join(dir, "leaf.key")
	writeLeafKeypair(t, certPath, keyPath)

	if _, err := NewSignerFromFiles(certPath, keyPath); err == nil {
		t.Error("NewSignerFromFiles accepted a non-CA cert")
	}
}

// --- helpers ---

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MUTHUR Test Intermediate"},
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
	cert, _ := x509.ParseCertificate(der)
	return &Signer{caCert: cert, caKey: priv, MaxLeafDuration: 30 * 24 * time.Hour}
}

func makeCSR(t *testing.T, cn string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("csr key: %v", err)
	}
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), priv
}

func makeCSRBytes(t *testing.T, cn string) []byte {
	pemBytes, _ := makeCSR(t, cn)
	return pemBytes
}

// mangleCSRSignature flips a byte in the encoded CSR after the signature
// region so the signature no longer matches. Used to drive Sign's rejection
// path.
func mangleCSRSignature(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("decode csr pem")
	}
	// Flip last byte (always lives inside the signature region of a CSR).
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	return pem.EncodeToMemory(block)
}

func parseLeafPEM(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("decode leaf pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

// writeIntermediate writes a real self-signed CA cert + PKCS#8 key to disk so
// NewSignerFromFiles can be exercised end-to-end.
func writeIntermediate(t *testing.T, certPath, keyPath string) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MUTHUR Test Intermediate"},
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
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeLeafKeypair(t *testing.T, certPath, keyPath string) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         false,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}
