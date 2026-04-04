package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds environment-derived settings for the muthur server.
// Notification receivers are NOT configured here — they are loaded from
// the config file pointed to by ConfigFile.
type Config struct {
	Port                   string
	LogLevel               string
	AnthropicAPIKey        string
	AnthropicModel         string
	Collectors             []CollectorConfig
	AlertManagerURL        string
	AlertManagerSilenceOn  bool
	AlertManagerSilenceDur time.Duration
	DedupWindowMinutes     int
	GrafanaBaseURL         string
	ConfigFile             string
}

type CollectorConfig struct {
	ClusterID string
	Token     string
}

func Load() (*Config, error) {
	dedupMin, _ := strconv.Atoi(envOr("DEDUP_WINDOW_MINUTES", "15"))

	silenceDur, err := time.ParseDuration(envOr("ALERTMANAGER_SILENCE_DURATION", "2h"))
	if err != nil {
		silenceDur = 2 * time.Hour
	}

	silenceEnabled, _ := strconv.ParseBool(envOr("ALERTMANAGER_SILENCE_ENABLED", "false"))

	cfg := &Config{
		Port:                   envOr("PORT", "8080"),
		LogLevel:               envOr("LOG_LEVEL", "info"),
		AnthropicAPIKey:        os.Getenv("ANTHROPIC_API_KEY"),
		AnthropicModel:         envOr("ANTHROPIC_MODEL", "claude-opus-4-5"),
		AlertManagerURL:        envOr("ALERTMANAGER_URL", "http://alertmanager.monitoring.svc:9093"),
		AlertManagerSilenceOn:  silenceEnabled,
		AlertManagerSilenceDur: silenceDur,
		DedupWindowMinutes:     dedupMin,
		GrafanaBaseURL:         os.Getenv("GRAFANA_BASE_URL"),
		ConfigFile:             envOr("MUTHUR_CONFIG_FILE", "/config/muthur.yaml"),
	}

	// Load collector tokens from COLLECTOR_TOKENS env (format: "clusterId:token,clusterId:token")
	if tokensEnv := os.Getenv("COLLECTOR_TOKENS"); tokensEnv != "" {
		for _, entry := range strings.Split(tokensEnv, ",") {
			parts := strings.SplitN(strings.TrimSpace(entry), ":", 2)
			if len(parts) == 2 {
				cfg.Collectors = append(cfg.Collectors, CollectorConfig{
					ClusterID: parts[0],
					Token:     parts[1],
				})
			}
		}
	}

	// Also load from individual env vars (COLLECTOR_TOKEN_<CLUSTER_ID>)
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "COLLECTOR_TOKEN_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				clusterID := strings.ToLower(strings.TrimPrefix(parts[0], "COLLECTOR_TOKEN_"))
				clusterID = strings.ReplaceAll(clusterID, "_", "-")
				cfg.Collectors = append(cfg.Collectors, CollectorConfig{
					ClusterID: clusterID,
					Token:     parts[1],
				})
			}
		}
	}

	if cfg.AnthropicAPIKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY is required")
	}
	if len(cfg.Collectors) == 0 {
		return nil, fmt.Errorf("at least one collector token must be configured")
	}

	return cfg, nil
}

func (c *Config) CollectorTokenMap() map[string]string {
	m := make(map[string]string, len(c.Collectors))
	for _, col := range c.Collectors {
		m[col.ClusterID] = col.Token
	}
	return m
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
