package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"
)

// Signer mints leaf certificates from CSRs using the vendor intermediate CA.
// Used by both the bootstrap path (first cert for a new collector) and the
// renewal path (/sign-csr). Identity is NEVER taken from the CSR: callers
// pass the authoritative Identity, and Sign only uses the CSR's public key.
// This means a forged CSR cannot change who the cert claims to be.
type Signer struct {
	caCert *x509.Certificate
	caKey  crypto.Signer

	// MaxLeafDuration caps the requested duration so a leaked or buggy caller
	// cannot mint a long-lived cert. Tests can override per case; production
	// uses NewSignerFromFiles which sets a 30-day cap.
	MaxLeafDuration time.Duration
}

// NewSignerFromFiles loads the intermediate CA cert + key from disk and
// returns a Signer ready to sign leaf certs. Both files must be PEM:
// the cert is a "CERTIFICATE" block, the key is "PRIVATE KEY" (PKCS#8),
// "EC PRIVATE KEY", or "RSA PRIVATE KEY".
func NewSignerFromFiles(certFile, keyFile string) (*Signer, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read intermediate cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read intermediate key: %w", err)
	}

	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate cert: %w", err)
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate key: %w", err)
	}

	if !cert.IsCA {
		return nil, errors.New("auth: intermediate certificate must have IsCA=true")
	}
	return &Signer{
		caCert:          cert,
		caKey:           key,
		MaxLeafDuration: 30 * 24 * time.Hour,
	}, nil
}

// Sign verifies the CSR, then mints a leaf cert that binds the supplied
// identity to the CSR's public key. The CSR's claimed Subject/SAN is ignored
// on purpose — identity is authoritative from the caller.
//
// duration is clamped to MaxLeafDuration. A zero or negative duration is
// treated as MaxLeafDuration so callers can request "as long as possible"
// by passing 0.
func (s *Signer) Sign(csrPEM []byte, id Identity, duration time.Duration) ([]byte, error) {
	csr, err := parseCSRPEM(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		// A failed signature means the caller does not control the matching
		// private key — refuse to sign.
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}

	if duration <= 0 || duration > s.MaxLeafDuration {
		duration = s.MaxLeafDuration
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	// Build the SPIFFE URI SAN from the authoritative identity. This is what
	// the brain (and any future relier) reads on every subsequent connection,
	// so the field MUST be canonical regardless of what the CSR asked for.
	var uris []*url.URL
	if id.TenantID != "" {
		u, _ := url.Parse("spiffe://muthur/" + id.TenantID + "/" + id.ClusterID)
		uris = append(uris, u)
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject, // common name only — informational, not auth-relevant
		URIs:         uris,
		NotBefore:    time.Now().Add(-1 * time.Minute), // small clock-skew tolerance
		NotAfter:     time.Now().Add(duration),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	// Always overwrite the Subject CN with the authoritative ClusterID so a
	// CSR cannot smuggle a different human-readable identity into the cert.
	tpl.Subject.CommonName = id.ClusterID

	der, err := x509.CreateCertificate(rand.Reader, tpl, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// CACertPEM returns the intermediate CA cert as PEM, so callers can return it
// alongside a freshly signed leaf to give clients the full chain.
func (s *Signer) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw})
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseCSRPEM(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// parseKeyPEM accepts PKCS#8 ("PRIVATE KEY"), SEC1 EC ("EC PRIVATE KEY"),
// and PKCS#1 RSA ("RSA PRIVATE KEY") since cert-manager has shipped all
// three forms over the years depending on configuration.
func parseKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return asSigner(key)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key PEM type %q", block.Type)
	}
}

func asSigner(key any) (crypto.Signer, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return k, nil
	case *rsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("key type %T is not a crypto.Signer", key)
	}
}

func randomSerial() (*big.Int, error) {
	// 159-bit random serial: well above RFC 5280's 20-octet ceiling and high
	// enough that collisions across the lifetime of the CA are negligible.
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	return rand.Int(rand.Reader, limit)
}
