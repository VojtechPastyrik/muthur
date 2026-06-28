package config

import (
	"os"
	"path/filepath"
	"testing"
)

// clearLLMEnv removes every env var that influences provider resolution so each
// test starts from a clean slate regardless of the developer's shell.
func clearLLMEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LLM_PROVIDER", "LLM_MODEL", "LLM_BASE_URL", "LLM_API_KEY_FILE",
		"LLM_SCHEMA_MODE", "LLM_TEMPERATURE", "LLM_MAX_RETRIES",
		"ANTHROPIC_API_KEY", "ANTHROPIC_MODEL",
		"TLS_SERVER_CERT_FILE", "TLS_SERVER_KEY_FILE", "TLS_TRUST_ROOT_FILE",
		"INTERMEDIATE_CA_FILE", "INTERMEDIATE_KEY_FILE",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

// setupTLS satisfies Load's mTLS-mandatory check without reading the files.
// Load only verifies the env vars are non-empty; the TLS plumbing reads the
// files later (at server startup), so dummy paths are fine here.
func setupTLS(t *testing.T) {
	t.Helper()
	t.Setenv("TLS_SERVER_CERT_FILE", "/tls/server.crt")
	t.Setenv("TLS_SERVER_KEY_FILE", "/tls/server.key")
	t.Setenv("TLS_TRUST_ROOT_FILE", "/tls/root.crt")
	t.Setenv("INTERMEDIATE_CA_FILE", "/tls/intermediate.crt")
	t.Setenv("INTERMEDIATE_KEY_FILE", "/tls/intermediate.key")
}

func TestLoad_DefaultsToAnthropic(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-legacy")
	setupTLS(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LLMProvider != "anthropic" {
		t.Errorf("provider = %q, want anthropic", cfg.LLMProvider)
	}
	if cfg.LLMModel != "claude-opus-4-5" {
		t.Errorf("model = %q, want claude-opus-4-5 (legacy default)", cfg.LLMModel)
	}
	if cfg.LLMAPIKey != "sk-legacy" {
		t.Errorf("api key = %q, want sk-legacy (ANTHROPIC_API_KEY back-compat)", cfg.LLMAPIKey)
	}
	if cfg.LLMSchemaMode != "auto" {
		t.Errorf("schema mode = %q, want auto", cfg.LLMSchemaMode)
	}
	if cfg.LLMMaxRetries != 1 {
		t.Errorf("max retries = %d, want 1", cfg.LLMMaxRetries)
	}
	if cfg.LLMTemperature != 0 {
		t.Errorf("temperature = %v, want 0", cfg.LLMTemperature)
	}
}

func TestLoad_AnthropicRequiresKey(t *testing.T) {
	clearLLMEnv(t)
	setupTLS(t)

	if _, err := Load(); err == nil {
		t.Error("want error when anthropic provider has no key")
	}
}

func TestLoad_OpenAICompatibleNoKey(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "openai-compatible")
	t.Setenv("LLM_BASE_URL", "http://ollama:11434/v1")
	t.Setenv("LLM_MODEL", "qwen2.5")
	setupTLS(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LLMProvider != "openai-compatible" {
		t.Errorf("provider = %q", cfg.LLMProvider)
	}
	if cfg.LLMBaseURL != "http://ollama:11434/v1" || cfg.LLMModel != "qwen2.5" {
		t.Errorf("base/model = %q/%q", cfg.LLMBaseURL, cfg.LLMModel)
	}
	if cfg.LLMAPIKey != "" {
		t.Errorf("api key = %q, want empty (keyless local)", cfg.LLMAPIKey)
	}
}

func TestLoad_OpenAICompatibleRequiresBaseAndModel(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "openai-compatible")
	t.Setenv("LLM_MODEL", "qwen2.5")
	setupTLS(t)

	if _, err := Load(); err == nil {
		t.Error("want error when openai-compatible has no base_url")
	}
}

func TestLoad_APIKeyFromFile(t *testing.T) {
	clearLLMEnv(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "llm-key")
	if err := os.WriteFile(keyPath, []byte("sk-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LLM_API_KEY_FILE", keyPath)
	setupTLS(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LLMAPIKey != "sk-from-file" {
		t.Errorf("api key = %q, want sk-from-file (trimmed)", cfg.LLMAPIKey)
	}
}

func TestLoad_UnknownProvider(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "gemini")
	setupTLS(t)

	if _, err := Load(); err == nil {
		t.Error("want error for unknown provider")
	}
}

func TestLoad_MissingTLSServerFilesFails(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-legacy")
	// Only intermediate set; server TLS missing → Load must refuse.
	t.Setenv("INTERMEDIATE_CA_FILE", "/tls/intermediate.crt")
	t.Setenv("INTERMEDIATE_KEY_FILE", "/tls/intermediate.key")

	if _, err := Load(); err == nil {
		t.Error("want error when TLS_SERVER_* env vars are unset")
	}
}

func TestLoad_MissingIntermediateFails(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-legacy")
	t.Setenv("TLS_SERVER_CERT_FILE", "/tls/server.crt")
	t.Setenv("TLS_SERVER_KEY_FILE", "/tls/server.key")
	t.Setenv("TLS_TRUST_ROOT_FILE", "/tls/root.crt")
	// Intermediate missing → Load must refuse: without it /sign-csr cannot
	// mint renewals.

	if _, err := Load(); err == nil {
		t.Error("want error when INTERMEDIATE_* env vars are unset")
	}
}

func TestLoad_ReplayWindowDefault(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-legacy")
	setupTLS(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ReplayWindow.String() != "5m0s" {
		t.Errorf("replay window = %s, want 5m0s default", cfg.ReplayWindow)
	}
}
