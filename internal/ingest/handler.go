package ingest

import (
	"context"
	"errors"
	"sync"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// Ingest-related sentinel errors. The gRPC adapter maps them:
//
//	ErrIngestNoIdentity → codes.Unauthenticated
//	ErrIngestForbidden  → codes.PermissionDenied (cluster_id mismatch)
var (
	ErrIngestNoIdentity = errors.New("ingest: no identity in context")
	ErrIngestForbidden  = errors.New("ingest: payload cluster_id does not match cert identity")
)

// Handler accepts collector-pushed alert payloads. Authentication is performed
// by the upstream gRPC auth interceptor — Handler trusts that an Identity is
// present in the request context. It then enforces:
//
//  1. Identity binding: the payload's self-declared cluster_id must equal the
//     cluster_id authenticated from the client certificate. A collector with
//     a cert for cluster A cannot ship data labelled as cluster B.
//
// Replay protection is enforced by a surrounding interceptor and not visible
// here.
type Handler struct {
	processor Processor
	logger    *zap.Logger
	wg        sync.WaitGroup
}

// Wait blocks until all in-flight alert-processing goroutines have finished.
// Used for graceful shutdown.
func (h *Handler) Wait() { h.wg.Wait() }

type Processor interface {
	Process(payload *pb.AlertPayload)
}

func NewHandler(processor Processor, logger *zap.Logger) *Handler {
	return &Handler{
		processor: processor,
		logger:    logger,
	}
}

// Ingest validates the payload against the authenticated identity and queues
// it for asynchronous processing. Returns immediately after enqueue (mirrors
// the previous 202 Accepted behaviour) so the collector's RPC deadline isn't
// blocked by a multi-second LLM call. The WaitGroup lets graceful shutdown
// drain in-flight work.
func (h *Handler) Ingest(ctx context.Context, payload *pb.AlertPayload) error {
	// Identity is set by the auth interceptor. Its absence here means the
	// RPC was mounted without that interceptor — a wiring bug we want to
	// fail closed on.
	id, ok := auth.FromContext(ctx)
	if !ok {
		h.logger.Warn("ingest reached without identity — interceptor not mounted?")
		return ErrIngestNoIdentity
	}

	// Cross-check the payload's self-declared cluster_id against the
	// authenticated identity. This is the load-bearing isolation between
	// tenants: a compromised or malicious collector cannot ship data
	// labelled as a different cluster.
	if payload.ClusterId != id.ClusterID {
		h.logger.Warn("payload cluster_id does not match cert identity",
			zap.String("payload_cluster_id", payload.ClusterId),
			zap.String("cert_cluster_id", id.ClusterID),
		)
		return ErrIngestForbidden
	}

	h.logger.Info("received alert",
		zap.String("cluster_id", payload.ClusterId),
		zap.String("alert_name", payload.AlertName),
		zap.String("severity", payload.Severity),
		zap.String("namespace", payload.Namespace),
		zap.String("status", payload.Status),
	)

	// Process asynchronously — pipeline contains a Claude call that
	// routinely takes 5-15s and we don't want to hold the collector's RPC
	// open that long.
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.processor.Process(payload)
	}()

	return nil
}
