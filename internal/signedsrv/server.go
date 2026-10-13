// Package signedsrv exposes the Brain service over plain HTTP for collectors
// that cannot reach the mTLS listener end-to-end (TLS terminated by Cloudflare,
// a cloud load balancer, or any edge that does not pass client certs).
//
// Authentication moves from the TLS handshake into the request: the collector
// signs each request with its leaf certificate's key (RFC 9421 subset), and
// the payload is HPKE-sealed to the brain's key so the edge only ever sees
// ciphertext. The same handlers, tenants snapshot and replay guard back both
// transports; this package is the HTTP shim in the way grpcsrv is the gRPC
// one.
package signedsrv

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// Route paths of the signed transport, relative to the listener root.
const (
	PathKeys      = "/muthur/v1/keys"
	PathBootstrap = "/muthur/v1/bootstrap"
	PathIngest    = "/muthur/v1/ingest"
	PathSignCSR   = "/muthur/v1/sign-csr"
	PathHeartbeat = "/muthur/v1/heartbeat"

	// maxBody bounds a sealed request. The collector caps redacted logs at
	// 256 KiB and metrics are small; 8 MiB leaves headroom without letting
	// an anonymous caller (bootstrap) make the brain buffer arbitrary input.
	maxBody = 8 << 20
)

// Error codes carried in the JSON error body.
const (
	CodeBadRequest     = "bad_request"
	CodeBadDigest      = "bad_digest"
	CodeBadSignature   = "bad_signature"
	CodeBadCert        = "bad_cert"
	CodeUnknownTenant  = "unknown_tenant"
	CodeRevoked        = "revoked"
	CodeReplay         = "replay"
	CodeHPKEKeyUnknown = "hpke_key_unknown"
	CodeSealed         = "sealed_malformed"
	CodeUnauthorized   = "unauthenticated"
	CodeForbidden      = "forbidden"
	CodeNotFound       = "not_found"
	CodePrecondition   = "failed_precondition"
	CodeInternal       = "internal"
)

// Deps are the collaborators the signed server composes.
type Deps struct {
	Brain   pb.BrainServer
	Tenants auth.TenantsProvider
	Replay  *auth.ReplayGuard
	Keys    *auth.HPKEKeySet
	Trust   *auth.TrustPools
	Signer  *auth.Signer
	Logger  *zap.Logger
	Now     func() time.Time
}

type server struct {
	Deps
}

// New returns the HTTP handler for the signed transport.
func New(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &server{Deps: d}
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Get(PathKeys, s.keys)
	r.Post(PathBootstrap, s.bootstrap)
	r.Post(PathIngest, s.ingest)
	r.Post(PathSignCSR, s.signCSR)
	r.Post(PathHeartbeat, s.heartbeat)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return r
}

// KeysDocument is the /keys response. Payload is the JSON-encoded KeysPayload
// signed as opaque bytes by the intermediate CA key; Signer is that CA's DER
// certificate so the collector can verify the chain against its vendor
// bundle. Signing the raw bytes avoids any JSON canonicalisation.
type KeysDocument struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Signer    string `json:"signer"`
}

// KeysPayload lists the brain's HPKE public keys, active key first.
type KeysPayload struct {
	IssuedAt int64      `json:"issued_at"`
	Keys     []KeyEntry `json:"keys"`
}

// KeyEntry describes one encapsulation key.
type KeyEntry struct {
	KID       string `json:"kid"`
	KEM       string `json:"kem"`
	KDF       string `json:"kdf"`
	AEAD      string `json:"aead"`
	PublicKey string `json:"public_key"`
}

func (s *server) keys(w http.ResponseWriter, _ *http.Request) {
	payload := KeysPayload{IssuedAt: s.Now().Unix()}
	for _, k := range s.Keys.Public() {
		payload.Keys = append(payload.Keys, KeyEntry{
			KID:       k.KID,
			KEM:       auth.HPKEKEMName,
			KDF:       auth.HPKEKDFName,
			AEAD:      auth.HPKEAEADName,
			PublicKey: base64.StdEncoding.EncodeToString(k.Key.Bytes()),
		})
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, CodeInternal, "encode keys")
		return
	}
	sig, err := s.Signer.SignPayload(raw)
	if err != nil {
		s.Logger.Error("sign keys payload", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, CodeInternal, "sign keys")
		return
	}
	doc := KeysDocument{
		Payload:   base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(sig),
		Signer:    base64.StdEncoding.EncodeToString(s.Signer.CACert().Raw),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(doc)
}

func (s *server) bootstrap(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, PathBootstrap, false, func(ctx context.Context, in []byte) (proto.Message, error) {
		var req pb.BootstrapRequest
		if err := proto.Unmarshal(in, &req); err != nil {
			return nil, status.Error(codes.InvalidArgument, "malformed BootstrapRequest")
		}
		return s.Brain.BootstrapCert(ctx, &req)
	})
}

func (s *server) ingest(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, PathIngest, true, func(ctx context.Context, in []byte) (proto.Message, error) {
		var req pb.AlertPayload
		if err := proto.Unmarshal(in, &req); err != nil {
			return nil, status.Error(codes.InvalidArgument, "malformed AlertPayload")
		}
		return s.Brain.Ingest(ctx, &req)
	})
}

func (s *server) signCSR(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, PathSignCSR, true, func(ctx context.Context, in []byte) (proto.Message, error) {
		var req pb.SignCSRRequest
		if err := proto.Unmarshal(in, &req); err != nil {
			return nil, status.Error(codes.InvalidArgument, "malformed SignCSRRequest")
		}
		return s.Brain.SignCSR(ctx, &req)
	})
}

func (s *server) heartbeat(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, PathHeartbeat, true, func(ctx context.Context, in []byte) (proto.Message, error) {
		var req pb.HeartbeatRequest
		if err := proto.Unmarshal(in, &req); err != nil {
			return nil, status.Error(codes.InvalidArgument, "malformed HeartbeatRequest")
		}
		return s.Brain.Heartbeat(ctx, &req)
	})
}

// handle runs the common pipeline in the same order as the gRPC interceptor
// chain: digest → signature/identity → revocation → replay → unseal →
// handler → seal. Bootstrap skips the identity, revocation and replay steps
// exactly like its gRPC counterpart; the single-use token is its guard.
func (s *server) handle(w http.ResponseWriter, r *http.Request, path string, authenticated bool, call func(context.Context, []byte) (proto.Message, error)) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, auth.SealedContentType) {
		s.writeError(w, http.StatusUnsupportedMediaType, CodeBadRequest, "expected "+auth.SealedContentType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		s.writeError(w, http.StatusRequestEntityTooLarge, CodeBadRequest, "body too large or unreadable")
		return
	}
	if err := auth.VerifyContentDigest(r.Header, body); err != nil {
		s.writeError(w, http.StatusBadRequest, CodeBadDigest, err.Error())
		return
	}

	timestamp := strings.TrimSpace(r.Header.Get(auth.HeaderTimestamp))
	nonce := strings.TrimSpace(r.Header.Get(auth.HeaderNonce))
	kid := strings.TrimSpace(r.Header.Get(auth.HeaderHPKEKid))

	ctx := r.Context()
	if authenticated {
		id, ok := s.authenticate(w, r, path, timestamp, nonce)
		if !ok {
			return
		}
		ctx = auth.WithContext(ctx, id)
	}

	plaintext, sealer, err := s.Keys.OpenRequest(kid, path, timestamp, nonce, body)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUnknownHPKEKey):
			s.writeError(w, http.StatusBadRequest, CodeHPKEKeyUnknown, "unknown HPKE key id; refetch "+PathKeys)
		default:
			s.writeError(w, http.StatusBadRequest, CodeSealed, "cannot open sealed request")
		}
		return
	}

	resp, err := call(ctx, plaintext)
	if err != nil {
		st, code := grpcToHTTP(err)
		s.writeError(w, st, code, status.Convert(err).Message())
		return
	}
	out, err := proto.Marshal(resp)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, CodeInternal, "encode response")
		return
	}
	sealed, err := sealer.Seal(out)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, CodeInternal, "seal response")
		return
	}
	w.Header().Set("Content-Type", auth.SealedContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

// authenticate turns the signature headers into a verified auth.Identity or
// writes the error response and returns ok=false.
func (s *server) authenticate(w http.ResponseWriter, r *http.Request, path, timestamp, nonce string) (*auth.Identity, bool) {
	leaf, err := parseCertHeader(r.Header.Get(auth.HeaderCert))
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, CodeBadCert, "missing or malformed "+auth.HeaderCert)
		return nil, false
	}
	now := s.Now()
	if err := s.Trust.VerifyClientLeaf(leaf, now); err != nil {
		s.Logger.Warn("rejecting request with untrusted cert", zap.Error(err), zap.String("path", path))
		s.writeError(w, http.StatusUnauthorized, CodeBadCert, "certificate not trusted")
		return nil, false
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, CodeBadCert, "certificate key must be ECDSA P-256")
		return nil, false
	}
	info, err := auth.VerifyRequest(r.Method, path, r.Header, pub)
	if err != nil {
		s.Logger.Warn("signature verification failed", zap.Error(err), zap.String("path", path))
		s.writeError(w, http.StatusUnauthorized, CodeBadSignature, err.Error())
		return nil, false
	}
	if info.KeyID != auth.CertKeyID(leaf.Raw) {
		s.writeError(w, http.StatusUnauthorized, CodeBadSignature, "keyid does not match certificate")
		return nil, false
	}
	if ts, err := strconv.ParseInt(timestamp, 10, 64); err != nil || ts != info.Created {
		s.writeError(w, http.StatusUnauthorized, CodeBadSignature, "created does not match "+auth.HeaderTimestamp)
		return nil, false
	}

	id, err := auth.ExtractFromCert(leaf)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, CodeBadCert, "certificate carries no identity")
		return nil, false
	}

	tenants := s.Tenants.Current()
	if tenants == nil {
		s.writeError(w, http.StatusInternalServerError, CodeInternal, "tenants unavailable")
		return nil, false
	}
	tenant, ok := tenants.Lookup(id.ClusterID)
	if !ok {
		s.Logger.Warn("rejecting request from unknown tenant", zap.String("cluster_id", id.ClusterID), zap.String("path", path))
		s.writeError(w, http.StatusForbidden, CodeUnknownTenant, "tenant not configured")
		return nil, false
	}
	if tenant.Revoked {
		s.Logger.Warn("rejecting request from revoked tenant", zap.String("cluster_id", id.ClusterID), zap.String("path", path))
		s.writeError(w, http.StatusForbidden, CodeRevoked, "tenant revoked")
		return nil, false
	}

	if err := s.Replay.Verify(r.Context(), id, timestamp, nonce); err != nil {
		st, code := http.StatusUnauthorized, CodeReplay
		switch {
		case errors.Is(err, auth.ErrReplayMissingTimestamp),
			errors.Is(err, auth.ErrReplayBadTimestamp),
			errors.Is(err, auth.ErrReplayMissingNonce),
			errors.Is(err, auth.ErrReplayBadNonce):
			st, code = http.StatusBadRequest, CodeBadRequest
		}
		s.Logger.Warn("replay check failed", zap.Error(err), zap.String("identity", id.String()), zap.String("path", path))
		s.writeError(w, st, code, err.Error())
		return nil, false
	}
	return id, true
}

func parseCertHeader(v string) (*x509.Certificate, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, errors.New("empty")
	}
	der, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// grpcToHTTP maps the status codes grpcsrv produces onto HTTP so a collector
// classifies permanent vs transient failures the same way on both transports.
func grpcToHTTP(err error) (int, string) {
	switch status.Code(err) {
	case codes.InvalidArgument:
		return http.StatusBadRequest, CodeBadRequest
	case codes.Unauthenticated:
		return http.StatusUnauthorized, CodeUnauthorized
	case codes.PermissionDenied:
		return http.StatusForbidden, CodeForbidden
	case codes.NotFound:
		return http.StatusNotFound, CodeNotFound
	case codes.FailedPrecondition:
		return http.StatusPreconditionFailed, CodePrecondition
	case codes.Unavailable:
		return http.StatusServiceUnavailable, CodeInternal
	default:
		return http.StatusInternalServerError, CodeInternal
	}
}

// ErrorBody is the plaintext JSON error response. It never carries request
// content, so leaving it unsealed exposes nothing to the edge.
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (s *server) writeError(w http.ResponseWriter, st int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(st)
	_ = json.NewEncoder(w).Encode(ErrorBody{Error: code, Message: msg})
}
