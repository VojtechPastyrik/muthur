// Package grpcsrv adapts the brain's pure handler logic (auth.BootstrapHandler,
// auth.RenewHandler, ingest.Handler) onto the gRPC Brain service generated
// from proto/alert.proto.
//
// The handlers themselves carry no transport awareness — this package is the
// thin shim that maps their typed errors to gRPC status codes.
package grpcsrv

import (
	"context"
	"errors"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	"github.com/VojtechPastyrik/muthur/internal/fleet"
	"github.com/VojtechPastyrik/muthur/internal/ingest"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// Server implements pb.BrainServer by composing the existing handlers.
type Server struct {
	pb.UnimplementedBrainServer

	bootstrap *auth.BootstrapHandler
	renew     *auth.RenewHandler
	ingest    *ingest.Handler
	fleet     *fleet.Tracker
	logger    *zap.Logger
}

// New wires the server. All dependencies must be non-nil; the auth + replay
// interceptors that gate Ingest, SignCSR and Heartbeat are configured
// separately in cmd/muthur.
func New(bootstrap *auth.BootstrapHandler, renew *auth.RenewHandler, ing *ingest.Handler, tracker *fleet.Tracker, logger *zap.Logger) *Server {
	return &Server{
		bootstrap: bootstrap,
		renew:     renew,
		ingest:    ing,
		fleet:     tracker,
		logger:    logger,
	}
}

// Heartbeat records a collector liveness beat. The cluster identity comes from
// the verified client certificate, never the request body.
func (s *Server) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	id, ok := auth.FromContext(ctx)
	if !ok || id == nil {
		return nil, status.Error(codes.Unauthenticated, fleet.ErrNoIdentity.Error())
	}
	if err := s.fleet.Record(ctx, id.ClusterID, req); err != nil {
		switch {
		case errors.Is(err, fleet.ErrNoIdentity):
			return nil, status.Error(codes.Unauthenticated, err.Error())
		case errors.Is(err, fleet.ErrForbidden):
			return nil, status.Error(codes.PermissionDenied, err.Error())
		default:
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return &pb.HeartbeatResponse{}, nil
}

func (s *Server) Ingest(ctx context.Context, payload *pb.AlertPayload) (*pb.IngestResponse, error) {
	if err := s.ingest.Ingest(ctx, payload); err != nil {
		switch {
		case errors.Is(err, ingest.ErrIngestNoIdentity):
			return nil, status.Error(codes.Unauthenticated, err.Error())
		case errors.Is(err, ingest.ErrIngestForbidden):
			return nil, status.Error(codes.PermissionDenied, err.Error())
		default:
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return &pb.IngestResponse{}, nil
}

func (s *Server) BootstrapCert(ctx context.Context, req *pb.BootstrapRequest) (*pb.BootstrapResponse, error) {
	res, err := s.bootstrap.Issue(ctx, auth.BootstrapInput{
		ClusterID:      req.GetClusterId(),
		BootstrapToken: req.GetBootstrapToken(),
		CSRPEM:         req.GetCsr(),
	})
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrBootstrapBadRequest):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, auth.ErrBootstrapUnauthorized):
			return nil, status.Error(codes.Unauthenticated, err.Error())
		case errors.Is(err, auth.ErrBootstrapForbidden):
			return nil, status.Error(codes.PermissionDenied, err.Error())
		case errors.Is(err, auth.ErrBootstrapInternal):
			return nil, status.Error(codes.Internal, err.Error())
		default:
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return &pb.BootstrapResponse{Certificate: res.CertificatePEM, Ca: res.CAPEM}, nil
}

func (s *Server) SignCSR(ctx context.Context, req *pb.SignCSRRequest) (*pb.SignCSRResponse, error) {
	res, err := s.renew.Issue(ctx, auth.RenewInput{CSRPEM: req.GetCsr()})
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrRenewBadRequest):
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, auth.ErrRenewForbidden):
			return nil, status.Error(codes.PermissionDenied, err.Error())
		case errors.Is(err, auth.ErrNoIdentity):
			return nil, status.Error(codes.Unauthenticated, err.Error())
		default:
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return &pb.SignCSRResponse{Certificate: res.CertificatePEM, Ca: res.CAPEM}, nil
}
