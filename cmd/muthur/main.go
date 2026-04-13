package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/VojtechPastyrik/muthur/internal/appconfig"
	"github.com/VojtechPastyrik/muthur/internal/config"
	"github.com/VojtechPastyrik/muthur/internal/dedup"
	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	"github.com/VojtechPastyrik/muthur/internal/ingest"
	"github.com/VojtechPastyrik/muthur/internal/llmcache"
	"github.com/VojtechPastyrik/muthur/internal/notify"
	"github.com/VojtechPastyrik/muthur/internal/pipeline"
	"github.com/VojtechPastyrik/muthur/internal/routing"
	"github.com/VojtechPastyrik/muthur/internal/silence"
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

	// Evaluator (Claude)
	eval := evaluator.New(cfg.AnthropicAPIKey, cfg.AnthropicModel, logger)

	// Dedup
	dd := dedup.New(cfg.DedupWindowMinutes, logger)

	// LLM response cache
	cache := llmcache.New(cfg.LLMCacheEnabled, cfg.LLMCacheTTLMinutes, logger)

	// Router
	router := routing.New(fileCfg.Routing.Rules, logger)

	// Silence
	silenceClient := silence.NewClient(
		cfg.AlertManagerURL,
		cfg.AlertManagerSilenceDur,
		cfg.AlertManagerSilenceOn,
		logger,
	)

	// Pipeline
	pipe := pipeline.New(dd, eval, cache, router, notifiers, silenceClient, logger)

	// HTTP server
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	handler := ingest.NewHandler(cfg.CollectorTokenMap(), pipe, logger)
	r.Post("/ingest", handler.ServeHTTP)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := fmt.Sprintf(":%s", cfg.Port)
	logger.Info("starting muthur", zap.String("addr", addr))
	return http.ListenAndServe(addr, r)
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
