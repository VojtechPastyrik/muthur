package auth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// ServerTLSConfig is the file paths needed to bring up the brain's mTLS
// listener. All three are required: cert-manager mounts them into the pod
// from the muthur-system Secrets.
type ServerTLSConfig struct {
	// CertFile and KeyFile point at the brain's own server certificate,
	// rotated by cert-manager. They are re-read on every TLS handshake when
	// the file mtime advances, so renewals take effect without a restart.
	CertFile string
	KeyFile  string

	// TrustRootFile is the vendor root CA. Client certs presented by
	// collectors must chain to this single trust anchor. Loaded once at
	// startup; root rotation is rare enough to justify a restart.
	TrustRootFile string
}

// LoadServerTLS returns a *tls.Config configured for mTLS:
//   - server cert sourced through a self-reloading callback (file mtime watch)
//   - client cert OPTIONAL but verified against the vendor trust root when
//     presented (VerifyClientCertIfGiven). The /bootstrap-cert endpoint serves
//     collectors that don't yet hold a cert, so a hard "require" at the TLS
//     layer would lock new clients out. The Middleware enforces presence on
//     routes that require an authenticated identity.
//   - TLS 1.2 minimum
//
// The returned config is safe to share across the http.Server lifetime; it
// holds no goroutines and reloads lazily on incoming handshakes.
func LoadServerTLS(cfg ServerTLSConfig) (*tls.Config, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.TrustRootFile == "" {
		return nil, errors.New("auth: ServerTLSConfig requires CertFile, KeyFile, TrustRootFile")
	}

	reloader, err := newCertReloader(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	pool, err := loadCertPool(cfg.TrustRootFile)
	if err != nil {
		return nil, fmt.Errorf("load trust root: %w", err)
	}

	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.VerifyClientCertIfGiven,
		ClientCAs:      pool,
		GetCertificate: reloader.getCertificate,
	}, nil
}

// loadCertPool reads a PEM file (one or more certificates) and returns a pool
// suitable for ClientCAs / RootCAs. Used for the vendor trust root that
// authenticates collector client certs.
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return pool, nil
}

// certReloader hot-reloads a TLS keypair when the underlying file changes,
// without dragging in a filesystem-watching dependency. Every handshake stats
// the cert file; if the mtime has advanced past the cached state, the keypair
// is re-read. The atomic pointer keeps reads lock-free in the happy path.
//
// If a reload fails (e.g. cert-manager mid-write), the previously cached
// keypair is returned so the listener keeps serving traffic. New handshakes
// retry the load on every connection until the file settles.
type certReloader struct {
	certFile string
	keyFile  string
	cached   atomic.Pointer[reloaderState]
}

type reloaderState struct {
	cert  *tls.Certificate
	mtime time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	// Preload so startup fails fast on a missing/bad keypair instead of waiting
	// for the first connection.
	if _, err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

// getCertificate is the tls.Config.GetCertificate callback. The signature is
// imposed by crypto/tls; the *tls.ClientHelloInfo is unused because we serve a
// single cert per listener (no SNI-driven cert selection).
func (r *certReloader) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	info, err := os.Stat(r.certFile)
	if err != nil {
		// Stat failure: fall back to cached cert if we have one. Connections
		// keep working through a transient FS hiccup.
		if cached := r.cached.Load(); cached != nil {
			return cached.cert, nil
		}
		return nil, err
	}
	if cached := r.cached.Load(); cached != nil && !info.ModTime().After(cached.mtime) {
		return cached.cert, nil
	}
	return r.load()
}

func (r *certReloader) load() (*tls.Certificate, error) {
	info, err := os.Stat(r.certFile)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		// Reload failed but we may still have a usable cached cert. Keep
		// serving with it; the next handshake will retry.
		if cached := r.cached.Load(); cached != nil {
			return cached.cert, nil
		}
		return nil, err
	}
	r.cached.Store(&reloaderState{cert: &cert, mtime: info.ModTime()})
	return &cert, nil
}
