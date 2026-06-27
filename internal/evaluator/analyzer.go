package evaluator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/metrics"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// defaultAnthropicModel is the model used when the Anthropic provider is
// selected without an explicit model. Matches the historical default so a
// deployment that sets no new config behaves byte-for-byte as before.
const defaultAnthropicModel = "claude-opus-4-5"

// ErrDegraded signals that the LLM produced output that could not be validated
// against the canonical schema even after the corrective retries, so the caller
// should degrade to raw delivery. It is distinct from a transport error but the
// pipeline treats both the same way: deliver the raw alert, never parse loosely.
var ErrDegraded = errors.New("llm output failed validation after retries; degrading to raw delivery")

// Analyzer is the provider-agnostic contract the pipeline depends on. Every
// implementation MUST return a fully-populated, schema-valid Analysis or an
// error — never raw text the caller has to regex or markdown-parse.
type Analyzer interface {
	// Evaluate analyses a single alert.
	Evaluate(ctx context.Context, payload *pb.AlertPayload, examples []Example) (*Analysis, error)
	// EvaluateIncident analyses a group of correlated alerts as one incident.
	EvaluateIncident(ctx context.Context, payloads []*pb.AlertPayload, examples []Example) (*Analysis, error)
	// Name returns a stable identifier for metrics/logs, e.g. "anthropic".
	Name() string
}

// provider is the low-level backend: it turns a prompt into the raw JSON object
// the model produced for the analysis schema. Validation, corrective retries,
// and the degrade decision all live in the shared Evaluator above it, so each
// provider only has to map the canonical schema onto its native mechanism and
// handle its own transport.
type provider interface {
	// name is the stable provider identifier for metrics/logs.
	name() string
	// model is the configured model identifier.
	model() string
	// structured reports whether the backend can guarantee schema-valid output
	// natively. When false, results are best-effort and lean entirely on the
	// validate-retry-degrade path for the structured-output guarantee.
	structured() bool
	// complete sends the prompt and returns the raw JSON arguments the model
	// produced, plus token usage. Transport-level retries are the provider's
	// responsibility; a returned error is terminal for this call.
	complete(ctx context.Context, prompt string) (json.RawMessage, usage, error)
}

// usage is per-call token accounting reported by a provider.
type usage struct {
	input  int
	output int
}

// Config selects and configures the analysis backend.
type Config struct {
	// Provider is "anthropic" (default) or "openai-compatible".
	Provider string
	// Model is the model identifier. Empty selects the provider default
	// (Anthropic only — the OpenAI-compatible provider requires an explicit one).
	Model string
	// BaseURL overrides the endpoint for the OpenAI-compatible provider
	// (e.g. an Ollama/vLLM/OpenRouter URL). Ignored by Anthropic.
	BaseURL string
	// APIKey is the resolved key (from a mounted file, see config). May be empty
	// for keyless local endpoints such as Ollama.
	APIKey string
	// SchemaMode is "schema", "json-object", or "auto" (capability detection).
	// Applies only to the OpenAI-compatible provider.
	SchemaMode string
	// Temperature is sent on OpenAI-compatible requests. 0 maximises structured-
	// output determinism on small models. Ignored by Anthropic forced tool-use.
	Temperature float64
	// MaxRetries is the number of corrective structured-output retries before
	// degrading to raw delivery.
	MaxRetries int
	// Timeout bounds each individual LLM call.
	Timeout time.Duration
}

// Evaluator wraps a provider with the shared validate-retry-degrade loop and
// implements Analyzer. The loop is what upholds the structured-output guarantee
// uniformly across providers.
type Evaluator struct {
	provider   provider
	maxRetries int
	logger     *zap.Logger
}

// New selects a provider from cfg and returns an Analyzer. With an empty or
// "anthropic" provider it reproduces the original forced-tool-use behaviour.
func New(cfg Config, logger *zap.Logger) (*Evaluator, error) {
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}

	var p provider
	switch cfg.Provider {
	case "", "anthropic":
		model := cfg.Model
		if model == "" {
			model = defaultAnthropicModel
		}
		if cfg.APIKey == "" {
			return nil, errors.New("anthropic provider requires an API key (ANTHROPIC_API_KEY or LLM_API_KEY_FILE)")
		}
		p = newAnthropicProvider(cfg.APIKey, model, cfg.Timeout, logger)

	case "openai-compatible":
		if cfg.BaseURL == "" {
			return nil, errors.New("openai-compatible provider requires LLM_BASE_URL")
		}
		if cfg.Model == "" {
			return nil, errors.New("openai-compatible provider requires LLM_MODEL")
		}
		mode, err := parseSchemaMode(cfg.SchemaMode)
		if err != nil {
			return nil, err
		}
		op := newOpenAIProvider(cfg.BaseURL, cfg.APIKey, cfg.Model, mode, cfg.Temperature, cfg.Timeout, logger)
		// Preflight (warn-and-continue): surface a misconfigured base_url or a
		// missing model at boot instead of silently degrading every alert. A
		// failure never blocks startup — the LLM must never gate the monitor.
		op.preflight(context.Background())
		p = op

	default:
		return nil, fmt.Errorf("unknown LLM_PROVIDER %q (want \"anthropic\" or \"openai-compatible\")", cfg.Provider)
	}

	if !p.structured() {
		logger.Warn("LLM provider cannot guarantee structured output natively; results are best-effort and rely on validate-retry-degrade",
			zap.String("provider", p.name()),
			zap.String("model", p.model()),
		)
	}

	return &Evaluator{provider: p, maxRetries: cfg.MaxRetries, logger: logger}, nil
}

// Name reports the underlying provider identifier.
func (e *Evaluator) Name() string { return e.provider.name() }

// Evaluate analyses a single alert.
func (e *Evaluator) Evaluate(ctx context.Context, payload *pb.AlertPayload, examples []Example) (*Analysis, error) {
	return e.run(ctx, buildPrompt(payload, examples))
}

// EvaluateIncident analyses a group of correlated alerts as one incident.
func (e *Evaluator) EvaluateIncident(ctx context.Context, payloads []*pb.AlertPayload, examples []Example) (*Analysis, error) {
	return e.run(ctx, buildIncidentPrompt(payloads, examples))
}

// run is the structured-output guarantee. It calls the provider, validates the
// output against the canonical schema, and on failure retries once with a
// corrective instruction (up to maxRetries). When the retries are exhausted it
// returns ErrDegraded so the pipeline delivers the raw alert — a malformed
// response never reaches a fragile markdown/JSON parser.
func (e *Evaluator) run(ctx context.Context, prompt string) (*Analysis, error) {
	start := time.Now()
	name, model := e.provider.name(), e.provider.model()

	instruction := prompt
	var lastErr error
	for attempt := 0; attempt <= e.maxRetries; attempt++ {
		raw, u, err := e.provider.complete(ctx, instruction)
		if err != nil {
			// Transport error after the provider's own retries — not fixable by
			// a corrective prompt. Degrade to raw delivery.
			metrics.LLMCalls.WithLabelValues("error", name, model).Inc()
			metrics.LLMCallDuration.WithLabelValues(name, model).Observe(time.Since(start).Seconds())
			return nil, fmt.Errorf("%s call failed: %w", name, err)
		}

		metrics.LLMTokens.WithLabelValues("input", name, model).Add(float64(u.input))
		metrics.LLMTokens.WithLabelValues("output", name, model).Add(float64(u.output))

		analysis, verr := decodeAndValidate(raw)
		if verr == nil {
			metrics.LLMCalls.WithLabelValues("ok", name, model).Inc()
			metrics.LLMCallDuration.WithLabelValues(name, model).Observe(time.Since(start).Seconds())
			return analysis, nil
		}

		lastErr = verr
		metrics.LLMValidationFailures.WithLabelValues(name, model).Inc()
		e.logger.Warn("LLM output failed schema validation",
			zap.String("provider", name),
			zap.String("model", model),
			zap.Int("attempt", attempt+1),
			zap.Error(verr),
		)

		if attempt < e.maxRetries {
			metrics.LLMRetries.WithLabelValues(name, model).Inc()
			instruction = prompt + correctiveSuffix(verr)
		}
	}

	// Retries exhausted: degrade honestly rather than loosely parse. The final
	// validation failure was already counted inside the loop above.
	metrics.LLMDegraded.WithLabelValues(name, model).Inc()
	metrics.LLMCalls.WithLabelValues("error", name, model).Inc()
	metrics.LLMCallDuration.WithLabelValues(name, model).Observe(time.Since(start).Seconds())
	e.logger.Error("LLM output invalid after retries, degrading to raw delivery",
		zap.String("provider", name),
		zap.String("model", model),
		zap.Error(lastErr),
	)
	return nil, fmt.Errorf("%w: %v", ErrDegraded, lastErr)
}

// correctiveSuffix is appended to the prompt on a retry so the model can repair
// its previous, invalid output. It names the canonical contract explicitly.
func correctiveSuffix(err error) string {
	return fmt.Sprintf("\n\n=== Correction required ===\n"+
		"Your previous response was invalid: %s.\n"+
		"Respond again with a complete, schema-valid analysis. Include every required field "+
		"(severity, root_cause, evidence, action, confidence, grounding, silence) and use only the allowed "+
		"enum values: severity one of %v, confidence one of %v, grounding one of %v.",
		err, severityEnum, confidenceEnum, groundingEnum)
}
