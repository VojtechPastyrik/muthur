package auth

import (
	"net/http"

	"go.uber.org/zap"
)

// Middleware extracts the verified client identity from the TLS handshake
// state and attaches it to the request context. Downstream handlers that
// require auth must read it via FromContext and reject requests when it's
// absent.
//
// The TLS server config (LoadServerTLS) already enforces
// RequireAndVerifyClientCert, so reaching this middleware without a peer cert
// means the request bypassed mTLS termination (e.g. ingress misconfiguration,
// non-TLS test wiring). That case fails closed with 401 and is logged: a
// healthy production setup should never log it.
func Middleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				logger.Warn("ingest reached without verified client cert — check ingress mTLS passthrough",
					zap.String("remote_addr", r.RemoteAddr),
					zap.String("path", r.URL.Path),
				)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// PeerCertificates[0] is the leaf — the cert presented by the client.
			// Intermediates (if any) follow at higher indices and are already
			// chain-validated by the TLS stack before we get here.
			id, err := ExtractFromCert(r.TLS.PeerCertificates[0])
			if err != nil {
				logger.Warn("rejecting client cert without usable identity",
					zap.Error(err),
					zap.String("remote_addr", r.RemoteAddr),
				)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r.WithContext(WithContext(r.Context(), id)))
		})
	}
}
