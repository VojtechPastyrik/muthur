package main

import (
	"context"
	"fmt"
	"net"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/VojtechPastyrik/muthur/internal/appconfig"
	"github.com/VojtechPastyrik/muthur/internal/auth"
	"github.com/VojtechPastyrik/muthur/internal/config"
	"github.com/VojtechPastyrik/muthur/internal/dedup"
	"github.com/VojtechPastyrik/muthur/internal/embed"
	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	"github.com/VojtechPastyrik/muthur/internal/feedback"
	"github.com/VojtechPastyrik/muthur/internal/grpcsrv"
	"github.com/VojtechPastyrik/muthur/internal/history"
	"github.com/VojtechPastyrik/muthur/internal/ingest"
	"github.com/VojtechPastyrik/muthur/internal/llmcache"
	"github.com/VojtechPastyrik/muthur/internal/llmlimit"
	"github.com/VojtechPastyrik/muthur/internal/notify"
	"github.com/VojtechPastyrik/muthur/internal/pipeline"
	"github.com/VojtechPastyrik/muthur/internal/routing"
	"github.com/VojtechPastyrik/muthur/internal/silence"
	"github.com/VojtechPastyrik/muthur/internal/store"
	pb "github.com/VojtechPastyrik/muthur/proto"
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

	// Evaluator: provider-agnostic LLM backend (Anthropic by default).
	eval, err := evaluator.New(evaluator.Config{
		Provider:    cfg.LLMProvider,
		Model:       cfg.LLMModel,
		BaseURL:     cfg.LLMBaseURL,
		APIKey:      cfg.LLMAPIKey,
		SchemaMode:  cfg.LLMSchemaMode,
		Temperature: cfg.LLMTemperature,
		MaxRetries:  cfg.LLMMaxRetries,
		Timeout:     cfg.LLMTimeout,
		AuditMode:   cfg.LLMAuditMode,
	}, logger)
	if err != nil {
		return fmt.Errorf("init evaluator: %w", err)
	}
	logger.Info("LLM provider ready",
		zap.String("provider", eval.Name()),
		zap.String("model", cfg.LLMModel),
	)

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

	// mTLS plumbing. The server config does double duty: it terminates client
	// TLS (verifying collector certs against the vendor trust root) and
	// presents brain's own server cert (hot-reloaded by cert-manager).
	tlsCfg, err := auth.LoadServerTLS(auth.ServerTLSConfig{
		CertFile:           cfg.TLSServerCertFile,
		KeyFile:            cfg.TLSServerKeyFile,
		TrustRootFile:      cfg.TLSTrustRootFile,
		IntermediateCAFile: cfg.IntermediateCAFile,
	})
	if err != nil {
		return fmt.Errorf("load server TLS: %w", err)
	}

	// Replay guard backed by the shared store, so nonce uniqueness holds
	// across replicas when a Redis/Dragonfly backend is configured.
	replayGuard := auth.NewReplayGuard(st, cfg.ReplayWindow, cfg.RedisPrefix)

	// Intermediate CA used to sign collector CSRs. The signer is shared
	// between BootstrapCert (first issuance) and SignCSR (renewals).
	signer, err := auth.NewSignerFromFiles(cfg.IntermediateCAFile, cfg.IntermediateKeyFile)
	if err != nil {
		return fmt.Errorf("load intermediate CA: %w", err)
	}

	// Tenants are loaded from the same YAML config file the receivers live in
	// (vendor-managed via GitOps). The reloader stat-polls the file so a
	// `revoked: true` flag-flip takes effect within seconds — without it,
	// runtime revocation would require a brain restart and a leaked leaf cert
	// would stay usable until expiry.
	tenantsReloader, err := auth.NewTenantsReloader(cfg.ConfigFile, 5*time.Second, logger)
	if err != nil {
		return fmt.Errorf("load tenants: %w", err)
	}
	tenantsReloader.Start()
	defer tenantsReloader.Stop()
	logger.Info("tenants loaded", zap.Int("count", tenantsReloader.Current().Len()))

	bootstrapH := auth.NewBootstrapHandler(tenantsReloader, signer, st, cfg.RedisPrefix, logger)
	renewH := auth.NewRenewHandler(tenantsReloader, signer, logger)

	ingestH := ingest.NewHandler(pipe, logger)

	// --- gRPC mTLS server (port 8080) ---
	// Collectors talk to the brain over the Brain service. Auth + replay run
	// as unary interceptors; BootstrapCert is exempt from both because the
	// caller has no cert yet and the bootstrap token's single-use guarantee
	// replaces the nonce check.
	grpcSrv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.ChainUnaryInterceptor(
			grpcsrv.AuthInterceptor(logger),
			grpcsrv.RevocationInterceptor(tenantsReloader, logger),
			grpcsrv.ReplayInterceptor(replayGuard, logger),
		),
	)
	pb.RegisterBrainServer(grpcSrv, grpcsrv.New(bootstrapH, renewH, ingestH, logger))
	// Reflection lets operators poke the API with grpcurl in production; it
	// only exposes the schema, which we already publish in the proto repo.
	reflection.Register(grpcSrv)

	// --- Public HTTP listener (port 8081) ---
	// Plain HTTP for the browser-facing /feedback link emitted into
	// notifications, kubelet probes, and the Prometheus scrape. Lives on a
	// separate port so a public-facing ingress (Cloudflare proxy, Let's
	// Encrypt termination, …) can front it without colliding with the mTLS
	// passthrough that owns the gRPC port.
	publicRouter := chi.NewRouter()
	publicRouter.Use(middleware.Recoverer)
	publicRouter.Use(middleware.RealIP)

	publicRouter.Get("/feedback", fb.ServeHTTP)
	publicRouter.Handle("/metrics", promhttp.Handler())
	publicRouter.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	grpcAddr := fmt.Sprintf(":%s", cfg.Port)
	publicAddr := fmt.Sprintf(":%s", cfg.PublicPort)
	publicSrv := &http.Server{Addr: publicAddr, Handler: publicRouter}

	grpcLn, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("listen gRPC: %w", err)
	}

	// Listen in the background so the main goroutine can wait for a shutdown
	// signal and drain in-flight work. Both listeners report through the
	// same serveErr channel — the first failure exits the process.
	serveErr := make(chan error, 2)
	go func() {
		logger.Info("starting muthur (gRPC mTLS)", zap.String("addr", grpcAddr))
		if err := grpcSrv.Serve(grpcLn); err != nil {
			serveErr <- err
		}
	}()
	go func() {
		logger.Info("starting muthur (public)", zap.String("addr", publicAddr))
		if err := publicSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serveErr:
		return fmt.Errorf("server: %w", err)
	case <-ctx.Done():
	}

	logger.Info("shutdown signal received, draining")
	shCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop accepting new requests on BOTH listeners, flush buffered incidents,
	// then wait for in-flight processing to drain.
	_ = publicSrv.Shutdown(shCtx)
	stoppedGRPC := make(chan struct{})
	go func() {
		grpcSrv.GracefulStop()
		close(stoppedGRPC)
	}()
	select {
	case <-stoppedGRPC:
	case <-shCtx.Done():
		grpcSrv.Stop()
	}
	pipe.Drain()

	done := make(chan struct{})
	go func() {
		ingestH.Wait()
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
