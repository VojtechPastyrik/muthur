package evaluator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// schemaMode selects how the OpenAI-compatible provider asks for structured
// output.
type schemaMode int

const (
	// modeSchema asks for a JSON Schema response_format (strongest guarantee;
	// supported by OpenAI, vLLM, recent Ollama, etc).
	modeSchema schemaMode = iota
	// modeJSONObject asks only for a JSON object and relies on the prompt +
	// Go-side validation. The fallback for endpoints without schema support.
	modeJSONObject
	// modeAuto starts in schema mode and downgrades to json-object on the first
	// signal that the endpoint cannot honour a JSON Schema response_format.
	modeAuto
)

func parseSchemaMode(s string) (schemaMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return modeAuto, nil
	case "schema":
		return modeSchema, nil
	case "json-object", "json_object", "json":
		return modeJSONObject, nil
	default:
		return modeAuto, fmt.Errorf("unknown LLM_SCHEMA_MODE %q (want \"schema\", \"json-object\", or \"auto\")", s)
	}
}

// openAIProvider talks to any OpenAI Chat Completions-compatible endpoint:
// OpenAI itself, Ollama, vLLM, LM Studio, OpenRouter, Groq, Together, etc. One
// implementation covers them all — only base_url and model change.
type openAIProvider struct {
	httpClient  *http.Client
	baseURL     string
	apiKey      string
	mdl         string
	temperature float64
	logger      *zap.Logger

	mu sync.Mutex
	// mode is the effective request mode. Under modeAuto it may downgrade from
	// schema to json-object at runtime once. Guarded by mu.
	mode schemaMode
	// downgraded records that auto-detection fell back to json-object, so
	// structured() can honestly report best-effort.
	downgraded bool
}

func newOpenAIProvider(baseURL, apiKey, model string, mode schemaMode, temperature float64, timeout time.Duration, logger *zap.Logger) *openAIProvider {
	return &openAIProvider{
		httpClient:  &http.Client{Timeout: timeout},
		baseURL:     strings.TrimRight(baseURL, "/"),
		apiKey:      apiKey,
		mdl:         model,
		temperature: temperature,
		mode:        mode,
		logger:      logger,
	}
}

func (p *openAIProvider) name() string  { return "openai-compatible" }
func (p *openAIProvider) model() string { return p.mdl }

// structured reports whether the endpoint can guarantee schema-valid output.
// True only while in (or starting in) schema mode and not yet downgraded;
// json-object and post-downgrade are best-effort.
func (p *openAIProvider) structured() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return (p.mode == modeSchema || p.mode == modeAuto) && !p.downgraded
}

func (p *openAIProvider) currentMode() schemaMode {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mode
}

// downgrade switches an auto provider from schema to json-object after the
// endpoint rejected a JSON Schema response_format. Idempotent; logs once.
func (p *openAIProvider) downgrade() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mode == modeAuto && !p.downgraded {
		p.downgraded = true
		p.logger.Warn("endpoint rejected JSON Schema response_format; falling back to json-object mode (best-effort structured output)",
			zap.String("model", p.mdl),
		)
	}
}

// effectiveMode resolves modeAuto to a concrete request mode given downgrade
// state. modeAuto sends schema until a downgrade has occurred, then json-object.
func (p *openAIProvider) effectiveMode() schemaMode {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch p.mode {
	case modeJSONObject:
		return modeJSONObject
	case modeSchema:
		return modeSchema
	default: // modeAuto
		if p.downgraded {
			return modeJSONObject
		}
		return modeSchema
	}
}

// --- wire types ---

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model          string        `json:"model"`
	Messages       []chatMessage `json:"messages"`
	MaxTokens      int           `json:"max_tokens,omitempty"`
	Temperature    float64       `json:"temperature"`
	ResponseFormat any           `json:"response_format,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// jsonObjectInstruction is appended in json-object mode so the model knows the
// exact shape to produce (json-object mode constrains output to *a* JSON object,
// not *this* schema). The Go-side validator remains the real guarantee.
const jsonObjectInstruction = "\n\nRespond with a single JSON object and nothing else (no markdown, no prose) with exactly these keys: " +
	"severity (one of critical, warning, info), root_cause (string), evidence (string), action (string), " +
	"confidence (one of high, medium, low), grounding (one of stated, inferred), silence (boolean), " +
	"silence_reason (string, only when silence is true)."

// complete sends the prompt and returns the raw JSON object the model produced.
// It handles transport retries with backoff and, under modeAuto, a one-time
// downgrade from schema to json-object when the endpoint rejects the schema.
func (p *openAIProvider) complete(ctx context.Context, prompt string) (json.RawMessage, usage, error) {
	// Per-call bound comes from httpClient.Timeout, set at construction.
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			p.logger.Warn("retrying OpenAI-compatible API call",
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
			)
			select {
			case <-ctx.Done():
				return nil, usage{}, ctx.Err()
			case <-time.After(backoff):
			}
		}

		mode := p.effectiveMode()
		raw, u, schemaUnsupported, err := p.do(ctx, prompt, mode)
		if err == nil {
			return raw, u, nil
		}
		lastErr = err

		// Schema rejected on an auto provider: downgrade and retry immediately
		// (this attempt was effectively a probe, not a real failure).
		if schemaUnsupported && p.currentMode() == modeAuto {
			p.downgrade()
			continue
		}
	}

	return nil, usage{}, fmt.Errorf("openai-compatible chat failed after 3 attempts: %w", lastErr)
}

// do performs a single chat completion. It returns the raw content JSON, token
// usage, a flag indicating the endpoint rejected the JSON Schema response_format
// (so the caller can downgrade), and an error.
func (p *openAIProvider) do(ctx context.Context, prompt string, mode schemaMode) (json.RawMessage, usage, bool, error) {
	userContent := prompt
	if mode == modeJSONObject {
		userContent += jsonObjectInstruction
	}

	reqBody := chatRequest{
		Model:          p.mdl,
		Messages:       []chatMessage{{Role: "user", Content: userContent}},
		MaxTokens:      1024,
		Temperature:    p.temperature,
		ResponseFormat: responseFormat(mode),
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, usage{}, false, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, usage{}, false, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, usage{}, false, fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		unsupported := schemaRejected(resp.StatusCode, respBody)
		return nil, usage{}, unsupported, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var cr chatResponse
	if err := json.Unmarshal(respBody, &cr); err != nil {
		return nil, usage{}, false, fmt.Errorf("decode response: %w", err)
	}
	if cr.Error != nil {
		return nil, usage{}, false, fmt.Errorf("api error: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return nil, usage{}, false, fmt.Errorf("response has no choices")
	}

	content := strings.TrimSpace(cr.Choices[0].Message.Content)
	if content == "" {
		return nil, usage{}, false, fmt.Errorf("response content empty")
	}

	u := usage{input: cr.Usage.PromptTokens, output: cr.Usage.CompletionTokens}
	// Return the content verbatim as raw JSON. It is validated by the shared
	// loop; there is deliberately no markdown stripping or lenient parsing.
	return json.RawMessage(content), u, false, nil
}

// responseFormat builds the response_format field for the given mode.
func responseFormat(mode schemaMode) any {
	switch mode {
	case modeJSONObject:
		return map[string]any{"type": "json_object"}
	default: // modeSchema (modeAuto resolves to schema before downgrade)
		return map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "analysis",
				"strict": true,
				"schema": analysisJSONSchema(),
			},
		}
	}
}

// schemaRejected heuristically detects that the endpoint does not support the
// JSON Schema response_format, so an auto provider can downgrade. Conservative:
// only client-side status codes with a body that mentions the response_format /
// schema machinery count, so a genuine bad-request for other reasons is not
// misread as a capability gap.
func schemaRejected(status int, body []byte) bool {
	if status != http.StatusBadRequest && status != http.StatusNotFound &&
		status != http.StatusUnprocessableEntity && status != http.StatusNotImplemented {
		return false
	}
	b := strings.ToLower(string(body))
	for _, marker := range []string{"response_format", "json_schema", "json schema", "schema", "not supported", "unsupported", "unrecognized"} {
		if strings.Contains(b, marker) {
			return true
		}
	}
	return false
}

// preflight checks at startup that the endpoint is reachable and the model
// resolves, logging a warning on failure. It never blocks startup — a transient
// or down endpoint must not gate the monitor; alerts simply degrade until it
// recovers. Under modeAuto a schema rejection here also primes the downgrade.
func (p *openAIProvider) preflight(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	mode := p.effectiveMode()
	_, _, unsupported, err := p.do(ctx, "preflight: respond with a minimal valid analysis object.", mode)
	if unsupported && p.currentMode() == modeAuto {
		p.downgrade()
		// Re-probe in the downgraded mode so a reachable endpoint preflights clean.
		_, _, _, err = p.do(ctx, "preflight: respond with a minimal valid analysis object.", modeJSONObject)
	}
	if err != nil {
		p.logger.Warn("LLM endpoint preflight failed; starting anyway, alerts will degrade until it recovers",
			zap.String("provider", p.name()),
			zap.String("base_url", p.baseURL),
			zap.String("model", p.mdl),
			zap.Error(err),
		)
		return
	}
	p.logger.Info("LLM endpoint preflight ok",
		zap.String("provider", p.name()),
		zap.String("base_url", p.baseURL),
		zap.String("model", p.mdl),
		zap.Bool("structured", p.structured()),
	)
}
