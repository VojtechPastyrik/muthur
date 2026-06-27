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
		"ANTHROPIC_API_KEY", "ANTHROPIC_MODEL", "COLLECTOR_TOKENS",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func TestLoad_DefaultsToAnthropic(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-legacy")
	t.Setenv("COLLECTOR_TOKENS", "cluster-a:tok")

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
	t.Setenv("COLLECTOR_TOKENS", "cluster-a:tok")

	if _, err := Load(); err == nil {
		t.Error("want error when anthropic provider has no key")
	}
}

func TestLoad_OpenAICompatibleNoKey(t *testing.T) {
	clearLLMEnv(t)
	t.Setenv("LLM_PROVIDER", "openai-compatible")
	t.Setenv("LLM_BASE_URL", "http://ollama:11434/v1")
	t.Setenv("LLM_MODEL", "qwen2.5")
	t.Setenv("COLLECTOR_TOKENS", "cluster-a:tok")

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
	t.Setenv("COLLECTOR_TOKENS", "cluster-a:tok")

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
	t.Setenv("COLLECTOR_TOKENS", "cluster-a:tok")

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
	t.Setenv("COLLECTOR_TOKENS", "cluster-a:tok")

	if _, err := Load(); err == nil {
		t.Error("want error for unknown provider")
	}
}
