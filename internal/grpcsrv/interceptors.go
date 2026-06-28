package grpcsrv

import (
	"context"
	"errors"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// authExemptMethods are RPCs that must be reachable without a verified
// client cert. /BootstrapCert is the only one — the bootstrap token in the
// request body authenticates it, and the collector legitimately has no
// cert yet on first call.
var authExemptMethods = map[string]struct{}{
	pb.Brain_BootstrapCert_FullMethodName: {},
}

// AuthInterceptor extracts the verified client identity from the TLS
// handshake state on the incoming connection and attaches it to the request
// context. Methods listed in authExemptMethods skip identity extraction.
//
// The server's TLS config sets ClientAuth=VerifyClientCertIfGiven so the
// bootstrap call can present no cert; for all other RPCs we require one and
// fail closed with Unauthenticated when it is absent.
func AuthInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, exempt := authExemptMethods[info.FullMethod]; exempt {
			return handler(ctx, req)
		}

		p, ok := peer.FromContext(ctx)
		if !ok || p == nil {
			logger.Warn("rpc reached without peer info — TLS not terminating here?",
				zap.String("method", info.FullMethod),
			)
			return nil, status.Error(codes.Unauthenticated, "no peer")
		}
		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
			logger.Warn("rpc reached without verified client cert — check ingress mTLS passthrough",
				zap.String("method", info.FullMethod),
				zap.String("remote", p.Addr.String()),
			)
			return nil, status.Error(codes.Unauthenticated, "no client cert")
		}

		// PeerCertificates[0] is the leaf — the cert presented by the client.
		// Intermediates (if any) follow at higher indices and are already
		// chain-validated by the TLS stack before we get here.
		id, err := auth.ExtractFromCert(tlsInfo.State.PeerCertificates[0])
		if err != nil {
			logger.Warn("rejecting client cert without usable identity",
				zap.Error(err),
				zap.String("method", info.FullMethod),
			)
			return nil, status.Error(codes.Unauthenticated, "no identity")
		}

		return handler(auth.WithContext(ctx, id), req)
	}
}

// ReplayInterceptor reads the freshness timestamp + single-use nonce from
// incoming metadata and verifies them via auth.ReplayGuard. Skipped for
// authExemptMethods — the bootstrap path has its own single-use guarantee
// based on the token, which is stronger than nonce uniqueness.
func ReplayInterceptor(guard *auth.ReplayGuard, logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, exempt := authExemptMethods[info.FullMethod]; exempt {
			return handler(ctx, req)
		}

		id, ok := auth.FromContext(ctx)
		if !ok {
			// AuthInterceptor must run first; missing identity here is a
			// wiring bug.
			logger.Warn("replay interceptor reached without identity — order bug?",
				zap.String("method", info.FullMethod),
			)
			return nil, status.Error(codes.Unauthenticated, "no identity")
		}

		md, _ := metadata.FromIncomingContext(ctx)
		ts := firstMeta(md, auth.MetaTimestamp)
		nonce := firstMeta(md, auth.MetaNonce)

		if err := guard.Verify(ctx, id, ts, nonce); err != nil {
			code := codes.Unauthenticated
			switch {
			case errors.Is(err, auth.ErrReplayMissingTimestamp),
				errors.Is(err, auth.ErrReplayBadTimestamp),
				errors.Is(err, auth.ErrReplayMissingNonce),
				errors.Is(err, auth.ErrReplayBadNonce):
				code = codes.InvalidArgument
			}
			logger.Warn("replay check failed",
				zap.Error(err),
				zap.String("identity", id.String()),
				zap.String("method", info.FullMethod),
			)
			return nil, status.Error(code, err.Error())
		}
		return handler(ctx, req)
	}
}

// firstMeta returns the first non-empty value for a metadata key, trimming
// surrounding whitespace. gRPC metadata is multi-valued; collectors only ever
// send one timestamp/nonce, but defensively grabbing the first lets the
// interceptor stay correct under unusual proxies.
func firstMeta(md metadata.MD, key string) string {
	for _, v := range md.Get(key) {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
