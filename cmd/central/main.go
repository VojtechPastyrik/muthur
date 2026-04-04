package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/VojtechPastyrik/muthur-central/internal/config"
	"github.com/VojtechPastyrik/muthur-central/internal/dedup"
	"github.com/VojtechPastyrik/muthur-central/internal/evaluator"
	"github.com/VojtechPastyrik/muthur-central/internal/ingest"
	"github.com/VojtechPastyrik/muthur-central/internal/notify"
	"github.com/VojtechPastyrik/muthur-central/internal/pipeline"
	"github.com/VojtechPastyrik/muthur-central/internal/routing"
	"github.com/VojtechPastyrik/muthur-central/internal/silence"
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

	// Evaluator
	eval := evaluator.New(cfg.AnthropicAPIKey, cfg.AnthropicModel, logger)

	// Dedup
	dd := dedup.New(cfg.DedupWindowMinutes, logger)

	// Router
	router, err := routing.NewRouter(cfg.RoutingRulesFile, logger)
	if err != nil {
		return fmt.Errorf("init router: %w", err)
	}

	// Notifiers
	notifiers := make(map[string]notify.Notifier)
	registerNotifiers(cfg, notifiers, logger)

	// Silence
	silenceClient := silence.NewClient(
		cfg.AlertManagerURL,
		cfg.AlertManagerSilenceDur,
		cfg.AlertManagerSilenceOn,
		logger,
	)

	// Pipeline
	pipe := pipeline.New(dd, eval, router, notifiers, silenceClient, cfg.GrafanaBaseURL, logger)

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
	logger.Info("starting muthur-central", zap.String("addr", addr))
	return http.ListenAndServe(addr, r)
}

func registerNotifiers(cfg *config.Config, notifiers map[string]notify.Notifier, logger *zap.Logger) {
	if cfg.TelegramToken != "" && cfg.TelegramChatID != "" {
		notifiers["telegram"] = notify.NewTelegram(cfg.TelegramToken, cfg.TelegramChatID)
		logger.Info("registered notifier", zap.String("name", "telegram"))
	} else {
		logger.Info("notifier disabled (missing config)", zap.String("name", "telegram"))
	}

	if cfg.DiscordWebhookURL != "" {
		notifiers["discord"] = notify.NewDiscord(cfg.DiscordWebhookURL)
		logger.Info("registered notifier", zap.String("name", "discord"))
	} else {
		logger.Info("notifier disabled (missing config)", zap.String("name", "discord"))
	}

	if cfg.SlackWebhookURL != "" {
		notifiers["slack"] = notify.NewSlack(cfg.SlackWebhookURL)
		logger.Info("registered notifier", zap.String("name", "slack"))
	} else {
		logger.Info("notifier disabled (missing config)", zap.String("name", "slack"))
	}

	if cfg.PagerDutyRoutingKey != "" {
		notifiers["pagerduty"] = notify.NewPagerDuty(cfg.PagerDutyRoutingKey)
		logger.Info("registered notifier", zap.String("name", "pagerduty"))
	} else {
		logger.Info("notifier disabled (missing config)", zap.String("name", "pagerduty"))
	}

	if cfg.GenericWebhookURL != "" {
		notifiers["webhook"] = notify.NewWebhook(cfg.GenericWebhookURL)
		logger.Info("registered notifier", zap.String("name", "webhook"))
	} else {
		logger.Info("notifier disabled (missing config)", zap.String("name", "webhook"))
	}
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
