package ingest

import (
	"errors"
	"io"
	"net/http"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/VojtechPastyrik/muthur/internal/auth"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// Handler accepts collector-pushed alert payloads. Authentication is performed
// by the upstream auth middleware (mTLS) — Handler trusts that an Identity is
// present in the request context. It then enforces:
//
//  1. Replay protection: timestamp window + single-use nonce (auth.ReplayGuard).
//  2. Identity binding: the payload's self-declared cluster_id must equal the
//     cluster_id authenticated from the client certificate. A collector with
//     a cert for cluster A cannot ship data labelled as cluster B.
type Handler struct {
	replay    *auth.ReplayGuard
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

func NewHandler(replay *auth.ReplayGuard, processor Processor, logger *zap.Logger) *Handler {
	return &Handler{
		replay:    replay,
		processor: processor,
		logger:    logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Identity is set by auth.Middleware. Its absence here means the route
	// was mounted without that middleware — a wiring bug we want to fail
	// closed on.
	id, ok := auth.FromContext(r.Context())
	if !ok {
		h.logger.Warn("ingest reached without identity — middleware not mounted?")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.replay.Verify(r.Context(), id, r); err != nil {
		// Map replay errors to status codes. Missing/malformed headers are
		// client bugs (400); reused nonce or stale timestamp is treated as
		// 401 because it's how a replayed-by-attacker request looks.
		status := http.StatusUnauthorized
		switch {
		case errors.Is(err, auth.ErrReplayMissingTimestamp),
			errors.Is(err, auth.ErrReplayBadTimestamp),
			errors.Is(err, auth.ErrReplayMissingNonce),
			errors.Is(err, auth.ErrReplayBadNonce):
			status = http.StatusBadRequest
		}
		h.logger.Warn("replay check failed",
			zap.Error(err),
			zap.String("identity", id.String()),
		)
		http.Error(w, http.StatusText(status), status)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("failed to read request body", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var payload pb.AlertPayload
	if err := proto.Unmarshal(body, &payload); err != nil {
		h.logger.Error("failed to unmarshal protobuf", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Cross-check the payload's self-declared cluster_id against the
	// authenticated identity. This is the load-bearing isolation between
	// tenants: a compromised or malicious collector cannot ship data labelled
	// as a different cluster.
	if payload.ClusterId != id.ClusterID {
		h.logger.Warn("payload cluster_id does not match cert identity",
			zap.String("payload_cluster_id", payload.ClusterId),
			zap.String("cert_cluster_id", id.ClusterID),
		)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	h.logger.Info("received alert",
		zap.String("cluster_id", payload.ClusterId),
		zap.String("alert_name", payload.AlertName),
		zap.String("severity", payload.Severity),
		zap.String("namespace", payload.Namespace),
		zap.String("status", payload.Status),
	)

	// Process asynchronously — pipeline contains a Claude call that routinely
	// takes 5-15s and we don't want to hold the collector's HTTP connection
	// (which itself is forwarded via an AlertManager webhook with a short
	// timeout). Caller gets 202 Accepted immediately. The WaitGroup lets
	// graceful shutdown drain in-flight work.
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.processor.Process(&payload)
	}()

	w.WriteHeader(http.StatusAccepted)
}
