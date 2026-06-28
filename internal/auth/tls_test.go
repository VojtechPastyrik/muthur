package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadServerTLS_RequiresAllPaths(t *testing.T) {
	if _, err := LoadServerTLS(ServerTLSConfig{}); err == nil {
		t.Error("LoadServerTLS with empty config: want error, got nil")
	}
}

func TestLoadServerTLS_Happy(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeServerCert(t, dir, "muthur-server")
	rootFile := writeRootCA(t, dir)

	cfg, err := LoadServerTLS(ServerTLSConfig{
		CertFile:      certFile,
		KeyFile:       keyFile,
		TrustRootFile: rootFile,
	})
	if err != nil {
		t.Fatalf("LoadServerTLS: %v", err)
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want >= TLS 1.2", cfg.MinVersion)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs is nil")
	}
	if cfg.GetCertificate == nil {
		t.Fatal("GetCertificate is nil")
	}

	// GetCertificate must succeed and return a non-nil cert.
	got, err := cfg.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got == nil || got.Certificate == nil {
		t.Fatal("GetCertificate returned nil cert")
	}
}

func TestLoadServerTLS_BadCertFile(t *testing.T) {
	dir := t.TempDir()
	rootFile := writeRootCA(t, dir)

	_, err := LoadServerTLS(ServerTLSConfig{
		CertFile:      filepath.Join(dir, "missing-cert.pem"),
		KeyFile:       filepath.Join(dir, "missing-key.pem"),
		TrustRootFile: rootFile,
	})
	if err == nil {
		t.Error("LoadServerTLS with missing cert file: want error, got nil")
	}
}

func TestLoadServerTLS_BadTrustRoot(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeServerCert(t, dir, "muthur-server")
	badRoot := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(badRoot, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadServerTLS(ServerTLSConfig{
		CertFile:      certFile,
		KeyFile:       keyFile,
		TrustRootFile: badRoot,
	})
	if err == nil {
		t.Error("LoadServerTLS with non-PEM trust root: want error, got nil")
	}
}

func TestCertReloader_HotReload(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeServerCert(t, dir, "first")

	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	first, err := r.getCertificate(nil)
	if err != nil {
		t.Fatalf("getCertificate first: %v", err)
	}
	firstLeaf, err := x509.ParseCertificate(first.Certificate[0])
	if err != nil {
		t.Fatalf("parse first leaf: %v", err)
	}
	if firstLeaf.Subject.CommonName != "first" {
		t.Fatalf("first CN = %q, want %q", firstLeaf.Subject.CommonName, "first")
	}

	// Overwrite the cert+key with a new keypair, bump mtime explicitly so the
	// reloader sees the change even on filesystems with coarse mtime.
	rewriteServerCert(t, certFile, keyFile, "second")
	bumpMtime(t, certFile)

	second, err := r.getCertificate(nil)
	if err != nil {
		t.Fatalf("getCertificate second: %v", err)
	}
	secondLeaf, err := x509.ParseCertificate(second.Certificate[0])
	if err != nil {
		t.Fatalf("parse second leaf: %v", err)
	}
	if secondLeaf.Subject.CommonName != "second" {
		t.Errorf("second CN = %q, want %q (hot reload failed)", secondLeaf.Subject.CommonName, "second")
	}
}

func TestCertReloader_KeepsCacheOnReloadFailure(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeServerCert(t, dir, "good")

	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	good, err := r.getCertificate(nil)
	if err != nil {
		t.Fatalf("getCertificate good: %v", err)
	}

	// Corrupt the cert file but bump mtime. The reloader must keep returning
	// the previously cached cert rather than crashing the listener.
	if err := os.WriteFile(certFile, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, certFile)

	got, err := r.getCertificate(nil)
	if err != nil {
		t.Fatalf("getCertificate after corruption: %v", err)
	}
	if got != good {
		t.Error("reloader did not keep cached cert after reload failure")
	}
}

func TestCertReloader_StableMtimeReusesCache(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeServerCert(t, dir, "stable")

	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	first, _ := r.getCertificate(nil)
	second, _ := r.getCertificate(nil)
	if first != second {
		t.Error("reloader re-loaded cert without mtime change (cache miss)")
	}
}

// writeServerCert generates a self-signed leaf and writes the cert + key as
// PEM into dir, returning the file paths.
func writeServerCert(t *testing.T, dir, cn string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	rewriteServerCert(t, certPath, keyPath, cn)
	return
}

func rewriteServerCert(t *testing.T, certPath, keyPath, cn string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeRootCA writes a self-signed CA cert as PEM into dir. Only the cert is
// retained (no key needed for the test — we only verify the file parses as a
// trust pool).
func writeRootCA(t *testing.T, dir string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MUTHUR Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	path := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// bumpMtime forces a strictly newer mtime on path, sidestepping coarse
// filesystem timestamps (some FS only have 1s mtime resolution).
func bumpMtime(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	future := st.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}
