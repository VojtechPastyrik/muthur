package ingest

import (
	"crypto/subtle"
	"io"
	"net/http"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

type Handler struct {
	tokenMap  map[string]string
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

func NewHandler(tokenMap map[string]string, processor Processor, logger *zap.Logger) *Handler {
	return &Handler{
		tokenMap:  tokenMap,
		processor: processor,
		logger:    logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("X-Collector-Token")
	if token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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

	expectedToken, ok := h.tokenMap[payload.ClusterId]
	if !ok {
		h.logger.Warn("unknown cluster", zap.String("cluster_id", payload.ClusterId))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Constant-time compare to avoid leaking the token via response timing.
	if subtle.ConstantTimeCompare([]byte(expectedToken), []byte(token)) != 1 {
		h.logger.Warn("token mismatch", zap.String("cluster_id", payload.ClusterId))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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
