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
	Port       string
	LogLevel   string
	LLMTimeout time.Duration
	Collectors []CollectorConfig

	// LLM provider abstraction. Provider defaults to "anthropic" so an existing
	// deployment with no new config behaves exactly as before. The resolved key
	// (LLMAPIKey) comes from LLM_API_KEY_FILE (preferred, a mounted Secret) or
	// the legacy ANTHROPIC_API_KEY env for back-compat.
	LLMProvider    string
	LLMModel       string
	LLMBaseURL     string
	LLMAPIKey      string
	LLMSchemaMode  string
	LLMTemperature float64
	LLMMaxRetries  int

	// Cost backstop: hard ceilings on LLM calls regardless of cache/dedup/
	// correlation. A storm of distinct, uncacheable alerts degrades to raw
	// delivery instead of an unbounded bill once these are hit.
	LLMMaxCallsPerMinute     int
	LLMBurst                 int
	LLMMaxConcurrent         int
	AlertManagerURL          string
	AlertManagerSilenceOn    bool
	AlertManagerSilenceDur   time.Duration
	AlertManagerSilenceAllow []string
	DedupWindowMinutes       int
	LLMCacheEnabled          bool
	LLMCacheTTLMinutes       int
	ConfigFile               string

	// Persistence. When RedisURL is set, dedup/cache/feedback state is shared
	// across replicas and survives restarts; otherwise an in-memory store is
	// used.
	RedisURL    string
	RedisPrefix string

	// Semantic cache reuses a prior analysis for a near-duplicate alert.
	SemanticCacheEnabled bool
	SemanticThreshold    float64
	EmbedDim             int

	// Alert correlation groups alerts that fire close together into one
	// incident (one LLM call, one notification).
	CorrelationEnabled       bool
	CorrelationWindowSeconds int
	CorrelationMaxGroup      int

	// Feedback. PublicURL must be set for feedback links to be emitted.
	PublicURL       string
	FeedbackFewShot int

	// Incident history persists each analysed incident under a stable ID for
	// later querying (Grafana, future MCP). Foundational and cheap; on by default.
	IncidentHistoryEnabled bool
	IncidentTTL            time.Duration

	// Evidence attaches curated redacted log lines + key metric facts to each
	// notification, so the alert is useful even when Claude is unavailable.
	EvidenceEnabled  bool
	EvidenceLogLines int
}

type CollectorConfig struct {
	ClusterID string
	Token     string
}

func Load() (*Config, error) {
	dedupMin, _ := strconv.Atoi(envOr("DEDUP_WINDOW_MINUTES", "15"))
	cacheTTL, _ := strconv.Atoi(envOr("LLM_CACHE_TTL_MINUTES", "30"))
	cacheEnabled, _ := strconv.ParseBool(envOr("LLM_CACHE_ENABLED", "true"))

	silenceDur, err := time.ParseDuration(envOr("ALERTMANAGER_SILENCE_DURATION", "2h"))
	if err != nil {
		silenceDur = 2 * time.Hour
	}

	silenceEnabled, _ := strconv.ParseBool(envOr("ALERTMANAGER_SILENCE_ENABLED", "false"))

	var silenceAllow []string
	if raw := os.Getenv("ALERTMANAGER_SILENCE_ALLOWLIST"); raw != "" {
		for _, name := range strings.Split(raw, ",") {
			if name = strings.TrimSpace(name); name != "" {
				silenceAllow = append(silenceAllow, name)
			}
		}
	}

	llmTimeout, err := time.ParseDuration(envOr("LLM_TIMEOUT", "20s"))
	if err != nil {
		llmTimeout = 20 * time.Second
	}

	llmMaxPerMin, _ := strconv.Atoi(envOr("LLM_MAX_CALLS_PER_MINUTE", "60"))
	llmBurst, _ := strconv.Atoi(envOr("LLM_BURST", "15"))
	llmMaxConcurrent, _ := strconv.Atoi(envOr("LLM_MAX_CONCURRENT", "8"))

	semanticEnabled, _ := strconv.ParseBool(envOr("SEMANTIC_CACHE_ENABLED", "false"))
	semanticThreshold, err := strconv.ParseFloat(envOr("SEMANTIC_CACHE_THRESHOLD", "0.95"), 64)
	if err != nil {
		semanticThreshold = 0.95
	}
	embedDim, _ := strconv.Atoi(envOr("SEMANTIC_CACHE_EMBED_DIM", "256"))

	correlationEnabled, _ := strconv.ParseBool(envOr("CORRELATION_ENABLED", "false"))
	correlationWindow, _ := strconv.Atoi(envOr("CORRELATION_WINDOW_SECONDS", "30"))
	correlationMaxGroup, _ := strconv.Atoi(envOr("CORRELATION_MAX_GROUP", "25"))

	fewShot, _ := strconv.Atoi(envOr("FEEDBACK_FEW_SHOT", "3"))

	historyEnabled, _ := strconv.ParseBool(envOr("INCIDENT_HISTORY_ENABLED", "true"))
	incidentTTL, err := time.ParseDuration(envOr("INCIDENT_TTL", "720h"))
	if err != nil {
		incidentTTL = 720 * time.Hour
	}
	evidenceEnabled, _ := strconv.ParseBool(envOr("NOTIFY_EVIDENCE_ENABLED", "true"))
	evidenceLogLines, _ := strconv.Atoi(envOr("NOTIFY_LOG_LINES", "8"))

	// --- LLM provider resolution (file-secret friendly, back-compatible) ---
	llmProvider := strings.ToLower(envOr("LLM_PROVIDER", "anthropic"))

	// Model: explicit LLM_MODEL wins; otherwise fall back to the legacy
	// ANTHROPIC_MODEL (which keeps the historical default) so the default
	// Anthropic path is byte-identical to before.
	llmModel := os.Getenv("LLM_MODEL")
	anthropicModel := envOr("ANTHROPIC_MODEL", "claude-opus-4-5")
	if llmModel == "" && (llmProvider == "anthropic" || llmProvider == "") {
		llmModel = anthropicModel
	}

	// API key: prefer a mounted file (LLM_API_KEY_FILE), fall back to the legacy
	// ANTHROPIC_API_KEY env. Keys never come from a plain *_API_KEY env going
	// forward — the file form matches the receiver-secret convention.
	apiKey, err := resolveAPIKey()
	if err != nil {
		return nil, err
	}

	llmSchemaMode := envOr("LLM_SCHEMA_MODE", "auto")
	llmTemperature, err := strconv.ParseFloat(envOr("LLM_TEMPERATURE", "0"), 64)
	if err != nil {
		llmTemperature = 0
	}
	llmMaxRetries, err := strconv.Atoi(envOr("LLM_MAX_RETRIES", "1"))
	if err != nil || llmMaxRetries < 0 {
		llmMaxRetries = 1
	}

	cfg := &Config{
		Port:                     envOr("PORT", "8080"),
		LogLevel:                 envOr("LOG_LEVEL", "info"),
		LLMProvider:              llmProvider,
		LLMModel:                 llmModel,
		LLMBaseURL:               os.Getenv("LLM_BASE_URL"),
		LLMAPIKey:                apiKey,
		LLMSchemaMode:            llmSchemaMode,
		LLMTemperature:           llmTemperature,
		LLMMaxRetries:            llmMaxRetries,
		LLMTimeout:               llmTimeout,
		LLMMaxCallsPerMinute:     llmMaxPerMin,
		LLMBurst:                 llmBurst,
		LLMMaxConcurrent:         llmMaxConcurrent,
		AlertManagerURL:          envOr("ALERTMANAGER_URL", "http://alertmanager.monitoring.svc:9093"),
		AlertManagerSilenceOn:    silenceEnabled,
		AlertManagerSilenceDur:   silenceDur,
		AlertManagerSilenceAllow: silenceAllow,
		DedupWindowMinutes:       dedupMin,
		LLMCacheEnabled:          cacheEnabled,
		LLMCacheTTLMinutes:       cacheTTL,
		ConfigFile:               envOr("MUTHUR_CONFIG_FILE", "/config/muthur.yaml"),

		RedisURL:    os.Getenv("REDIS_URL"),
		RedisPrefix: envOr("REDIS_PREFIX", "muthur:"),

		SemanticCacheEnabled: semanticEnabled,
		SemanticThreshold:    semanticThreshold,
		EmbedDim:             embedDim,

		CorrelationEnabled:       correlationEnabled,
		CorrelationWindowSeconds: correlationWindow,
		CorrelationMaxGroup:      correlationMaxGroup,

		PublicURL:       os.Getenv("MUTHUR_PUBLIC_URL"),
		FeedbackFewShot: fewShot,

		IncidentHistoryEnabled: historyEnabled,
		IncidentTTL:            incidentTTL,
		EvidenceEnabled:        evidenceEnabled,
		EvidenceLogLines:       evidenceLogLines,
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

	// Provider-aware validation. The default Anthropic path still requires a
	// key; the OpenAI-compatible path requires base_url + model but allows a
	// missing key (keyless local endpoints such as Ollama).
	switch cfg.LLMProvider {
	case "", "anthropic":
		if cfg.LLMAPIKey == "" {
			return nil, fmt.Errorf("an API key is required for the anthropic provider (set LLM_API_KEY_FILE or ANTHROPIC_API_KEY)")
		}
	case "openai-compatible":
		if cfg.LLMBaseURL == "" {
			return nil, fmt.Errorf("LLM_BASE_URL is required for the openai-compatible provider")
		}
		if cfg.LLMModel == "" {
			return nil, fmt.Errorf("LLM_MODEL is required for the openai-compatible provider")
		}
	default:
		return nil, fmt.Errorf("unknown LLM_PROVIDER %q (want \"anthropic\" or \"openai-compatible\")", cfg.LLMProvider)
	}

	if len(cfg.Collectors) == 0 {
		return nil, fmt.Errorf("at least one collector token must be configured")
	}

	return cfg, nil
}

// resolveAPIKey reads the LLM API key from a mounted file (LLM_API_KEY_FILE,
// the preferred, Secret-friendly form) and falls back to the legacy
// ANTHROPIC_API_KEY env for backward compatibility. Returns an empty string
// when neither is set — valid for keyless local endpoints; the provider-aware
// validation above enforces a key only where one is required.
func resolveAPIKey() (string, error) {
	if path := os.Getenv("LLM_API_KEY_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read LLM_API_KEY_FILE %q: %w", path, err)
		}
		return strings.TrimRight(string(data), " \t\r\n"), nil
	}
	return os.Getenv("ANTHROPIC_API_KEY"), nil
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
