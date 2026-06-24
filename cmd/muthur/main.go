package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/VojtechPastyrik/muthur/internal/appconfig"
	"github.com/VojtechPastyrik/muthur/internal/config"
	"github.com/VojtechPastyrik/muthur/internal/dedup"
	"github.com/VojtechPastyrik/muthur/internal/embed"
	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	"github.com/VojtechPastyrik/muthur/internal/feedback"
	"github.com/VojtechPastyrik/muthur/internal/history"
	"github.com/VojtechPastyrik/muthur/internal/ingest"
	"github.com/VojtechPastyrik/muthur/internal/llmcache"
	"github.com/VojtechPastyrik/muthur/internal/llmlimit"
	"github.com/VojtechPastyrik/muthur/internal/notify"
	"github.com/VojtechPastyrik/muthur/internal/pipeline"
	"github.com/VojtechPastyrik/muthur/internal/routing"
	"github.com/VojtechPastyrik/muthur/internal/silence"
	"github.com/VojtechPastyrik/muthur/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger, err := newLogger(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync()

	// Load receivers and routing rules from file.
	fileCfg, err := appconfig.Load(cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("load config file: %w", err)
	}

	// Build notifier instances from receiver configs (factory pattern).
	notifiers, err := notify.BuildReceivers(fileCfg.Receivers, logger)
	if err != nil {
		return fmt.Errorf("build receivers: %w", err)
	}
	if len(notifiers) == 0 {
		logger.Warn("no receivers registered — alerts will be evaluated but not delivered")
	}

	// Validate that every receiver referenced by routing rules exists.
	for _, rule := range fileCfg.Routing.Rules {
		for _, name := range rule.Receivers {
			if _, ok := notifiers[name]; !ok {
				logger.Warn("routing rule references unknown receiver",
					zap.String("rule", rule.Name),
					zap.String("receiver", name))
			}
		}
	}

	// Persistence: shared Redis/Dragonfly when configured, in-memory otherwise.
	st, err := newStore(cfg, logger)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}
	defer st.Close()
	logger.Info("state store ready", zap.String("kind", st.Kind()))

	// Evaluator (Claude)
	eval := evaluator.New(cfg.AnthropicAPIKey, cfg.AnthropicModel, cfg.LLMTimeout, logger)

	// Cost backstop: hard rate + concurrency ceiling on LLM calls. Nil when
	// disabled (limits non-positive), in which case the pipeline is unlimited.
	limiter := llmlimit.New(cfg.LLMMaxCallsPerMinute, cfg.LLMBurst, cfg.LLMMaxConcurrent, logger)
	if limiter != nil {
		logger.Info("LLM cost backstop enabled",
			zap.Int("calls_per_minute", cfg.LLMMaxCallsPerMinute),
			zap.Int("burst", cfg.LLMBurst),
			zap.Int("max_concurrent", cfg.LLMMaxConcurrent),
		)
	}

	// Dedup
	dd := dedup.New(cfg.DedupWindowMinutes, st, logger)

	// Semantic-cache embedder (local feature hashing — no external calls).
	var embedder embed.Embedder
	if cfg.SemanticCacheEnabled {
		embedder = embed.NewHashEmbedder(cfg.EmbedDim)
	}

	// LLM response cache (exact + optional semantic layer)
	cache := llmcache.New(cfg.LLMCacheEnabled, cfg.LLMCacheTTLMinutes, st, embedder,
		cfg.SemanticCacheEnabled, cfg.SemanticThreshold, logger)

	// Incident history (foundation for Grafana queries / future MCP).
	var hist *history.Store
	if cfg.IncidentHistoryEnabled {
		hist = history.New(st, cfg.IncidentTTL, logger)
		logger.Info("incident history enabled", zap.Duration("ttl", cfg.IncidentTTL))
	}

	// Feedback loop
	fb := feedback.New(st, cfg.PublicURL, cfg.FeedbackFewShot, logger)
	if fb.LinksEnabled() {
		logger.Info("feedback links enabled", zap.String("public_url", cfg.PublicURL))
	} else {
		logger.Info("feedback links disabled (set MUTHUR_PUBLIC_URL to enable)")
	}

	// Router
	router := routing.New(fileCfg.Routing.Rules, logger)

	// Silence
	silenceClient := silence.NewClient(
		cfg.AlertManagerURL,
		cfg.AlertManagerSilenceDur,
		cfg.AlertManagerSilenceOn,
		cfg.AlertManagerSilenceAllow,
		logger,
	)

	// Pipeline
	pipe := pipeline.New(dd, eval, cache, limiter, router, notifiers, silenceClient, fb, hist,
		notify.EvidenceConfig{Enabled: cfg.EvidenceEnabled, LogLines: cfg.EvidenceLogLines},
		pipeline.CorrelationConfig{
			Enabled:       cfg.CorrelationEnabled,
			WindowSeconds: cfg.CorrelationWindowSeconds,
			MaxGroup:      cfg.CorrelationMaxGroup,
		}, logger)
	if cfg.CorrelationEnabled {
		logger.Info("alert correlation enabled",
			zap.Int("window_seconds", cfg.CorrelationWindowSeconds),
			zap.Int("max_group", cfg.CorrelationMaxGroup),
		)
	}

	// HTTP server
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	handler := ingest.NewHandler(cfg.CollectorTokenMap(), pipe, logger)
	r.Post("/ingest", handler.ServeHTTP)

	// Operator feedback callback (GET /feedback?id=..&verdict=useful|wrong).
	r.Get("/feedback", fb.ServeHTTP)

	// Self-observability: Prometheus metrics.
	r.Handle("/metrics", promhttp.Handler())

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := fmt.Sprintf(":%s", cfg.Port)
	srv := &http.Server{Addr: addr, Handler: r}

	// Listen in the background so the main goroutine can wait for a shutdown
	// signal and drain in-flight work.
	serveErr := make(chan error, 1)
	go func() {
		logger.Info("starting muthur", zap.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serveErr:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	logger.Info("shutdown signal received, draining")
	shCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop accepting new requests, flush buffered incidents, then wait for
	// in-flight alert processing to finish (bounded by shCtx).
	_ = srv.Shutdown(shCtx)
	pipe.Drain()

	done := make(chan struct{})
	go func() {
		handler.Wait()
		close(done)
	}()
	select {
	case <-done:
		logger.Info("drained cleanly")
	case <-shCtx.Done():
		logger.Warn("drain timed out, exiting with in-flight work")
	}
	return nil
}

// newStore selects the persistence backend. A configured REDIS_URL gives a
// Redis/Dragonfly-backed store shared across replicas; otherwise an in-memory
// store is used (per-instance, lost on restart).
func newStore(cfg *config.Config, logger *zap.Logger) (store.Store, error) {
	if cfg.RedisURL == "" {
		return store.NewMemory(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return store.NewRedis(ctx, cfg.RedisURL, cfg.RedisPrefix)
}

func newLogger(level string) (*zap.Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	return cfg.Build()
}
