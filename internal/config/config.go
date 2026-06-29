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
	// Port is the mTLS listener that collectors hit for /ingest,
	// /sign-csr, and /bootstrap-cert. Behind a TLS-passthrough ingress.
	Port string

	// PublicPort is the plain-HTTP listener carrying browser-facing
	// /feedback links, kubelet probes, and Prometheus scrapes. Separate
	// listener so a public ingress can terminate TLS with a CA the browser
	// trusts (Let's Encrypt, Cloudflare) without colliding with the mTLS
	// passthrough on Port.
	PublicPort string

	LogLevel   string
	LLMTimeout time.Duration

	// mTLS server paths. All three are required: collectors authenticate via
	// a client cert that chains to TrustRootFile, and they verify the brain
	// using ServerCertFile/ServerKeyFile (rotated by cert-manager). The files
	// are mounted from Kubernetes Secrets.
	TLSServerCertFile string
	TLSServerKeyFile  string
	TLSTrustRootFile  string

	// IntermediateCAFile + IntermediateKeyFile are the keypair brain uses
	// to sign collector CSRs (/sign-csr and /bootstrap-cert). They MUST chain
	// to TrustRootFile, so collectors that are issued a cert under this
	// intermediate validate against the same trust anchor on subsequent
	// connections.
	IntermediateCAFile  string
	IntermediateKeyFile string

	// Replay-protection window applied to every authenticated request. The
	// nonce cache TTL is 2×this. Defaults to 5m when unset.
	ReplayWindow time.Duration

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
	// LLMAuditMode controls per-call audit logging of LLM input/output.
	//   "off"  — default. No audit log at all; minimal log volume.
	//   "hash" — log identity + SHA-256 of prompt/output, no bodies. Proves
	//            a call happened with a given input under the verified cert,
	//            without inflating logs by 200KB/alert on stacktrace-heavy
	//            payloads.
	//   "full" — log identity + hashes + full bodies. Only safe with an
	//            external retention sink (Loki + object-lock, SIEM, …);
	//            otherwise k8s container log rotation (10MB×5) eats the
	//            audit during a storm.
	LLMAuditMode string

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

// (CollectorConfig removed — token-based per-cluster credentials are replaced
// by mTLS in v0.7. Identity now comes from the verified client certificate.)

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

	replayWindow, err := time.ParseDuration(envOr("AUTH_REPLAY_WINDOW", "5m"))
	if err != nil {
		replayWindow = 5 * time.Minute
	}

	cfg := &Config{
		Port:                     envOr("PORT", "8080"),
		PublicPort:               envOr("PUBLIC_PORT", "8081"),
		LogLevel:                 envOr("LOG_LEVEL", "info"),
		TLSServerCertFile:        os.Getenv("TLS_SERVER_CERT_FILE"),
		TLSServerKeyFile:         os.Getenv("TLS_SERVER_KEY_FILE"),
		TLSTrustRootFile:         os.Getenv("TLS_TRUST_ROOT_FILE"),
		IntermediateCAFile:       os.Getenv("INTERMEDIATE_CA_FILE"),
		IntermediateKeyFile:      os.Getenv("INTERMEDIATE_KEY_FILE"),
		ReplayWindow:             replayWindow,
		LLMProvider:              llmProvider,
		LLMModel:                 llmModel,
		LLMBaseURL:               os.Getenv("LLM_BASE_URL"),
		LLMAPIKey:                apiKey,
		LLMSchemaMode:            llmSchemaMode,
		LLMTemperature:           llmTemperature,
		LLMMaxRetries:            llmMaxRetries,
		LLMAuditMode:             strings.ToLower(envOr("LLM_AUDIT_MODE", "off")),
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

	// mTLS is mandatory in v0.7. All five files must be configured; cert-manager
	// in the brain's namespace mounts them via the chart's Secret references.
	if cfg.TLSServerCertFile == "" || cfg.TLSServerKeyFile == "" || cfg.TLSTrustRootFile == "" {
		return nil, fmt.Errorf("TLS_SERVER_CERT_FILE, TLS_SERVER_KEY_FILE and TLS_TRUST_ROOT_FILE are required for mTLS")
	}
	if cfg.IntermediateCAFile == "" || cfg.IntermediateKeyFile == "" {
		return nil, fmt.Errorf("INTERMEDIATE_CA_FILE and INTERMEDIATE_KEY_FILE are required to sign collector CSRs")
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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
