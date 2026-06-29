package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/auth"
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

// Prompt carries the system/user split. System holds the behaviour rules
// (analysis rubric, anti-injection guidance, structured-output contract);
// User holds the alert data wrapped in <untrusted_alert_data>. Both providers
// emit this split natively — Anthropic via the `system` parameter, OpenAI via
// a `system`-role message — so attacker-controlled log text in User cannot
// override System rules as easily as it could when both were concatenated
// into one user-role string. The textual fence is kept as defence-in-depth.
type Prompt struct {
	System string
	User   string
}

// String returns the concatenated System+User text. Used by tests that assert
// content presence without caring which half it lives in; in production the
// two halves stay separate and go to distinct API roles.
func (p Prompt) String() string { return p.System + p.User }

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
	complete(ctx context.Context, prompt Prompt) (json.RawMessage, usage, error)
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
	// AuditMode controls per-call audit logging of LLM input/output. Values:
	//   "off"  — no audit log at all (default; minimum log volume)
	//   "hash" — log identity + SHA-256 hashes of prompt/output only; the
	//            payload bodies are NOT logged. Proves a call happened with a
	//            given input, without inflating logs by 200KB/call on
	//            stacktrace-heavy alerts.
	//   "full" — log identity + hashes + full prompt body + full output. Pick
	//            this only when an external retention sink (Loki/SIEM with
	//            object-lock storage) is in place; otherwise k8s ring buffer
	//            rotates the audit away within minutes during a storm.
	AuditMode string
	// AirGapped, when true, refuses any LLM provider that talks to a
	// cloud-managed inference endpoint. Today that means the native
	// "anthropic" provider is rejected; "openai-compatible" is accepted
	// (the operator is responsible for pointing LLM_BASE_URL at an
	// in-cluster Ollama / vLLM / LM Studio, not at api.openai.com).
	// Designed for regulated deployments where any cloud egress is a
	// compliance violation; pairs well with NetworkPolicy / egress
	// filtering to enforce the same invariant at the kernel level.
	AirGapped bool
}

// AuditMode controls how the LLM input/output audit log is emitted.
type AuditMode int

const (
	AuditOff  AuditMode = iota // no audit log
	AuditHash                  // identity + hashes only
	AuditFull                  // identity + hashes + full prompt/output bodies
)

// parseAuditMode normalises the string form from config. Unknown values fall
// back to AuditOff — failing safe by emitting nothing rather than accidentally
// shipping bodies into a misconfigured sink.
func parseAuditMode(s string) AuditMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "hash":
		return AuditHash
	case "full":
		return AuditFull
	default:
		return AuditOff
	}
}

// Evaluator wraps a provider with the shared validate-retry-degrade loop and
// implements Analyzer. The loop is what upholds the structured-output guarantee
// uniformly across providers.
type Evaluator struct {
	provider   provider
	maxRetries int
	auditMode  AuditMode
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
		if cfg.AirGapped {
			return nil, errors.New("air-gapped mode forbids the cloud-managed anthropic provider; set LLM_PROVIDER=openai-compatible and point LLM_BASE_URL at an in-cluster endpoint")
		}
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

	return &Evaluator{
		provider:   p,
		maxRetries: cfg.MaxRetries,
		auditMode:  parseAuditMode(cfg.AuditMode),
		logger:     logger,
	}, nil
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
func (e *Evaluator) run(ctx context.Context, prompt Prompt) (*Analysis, error) {
	start := time.Now()
	name, model := e.provider.name(), e.provider.model()
	// cluster_id is taken from the verified mTLS identity (RevocationInterceptor
	// has already enforced payload.cluster_id == cert.cluster_id, so this matches
	// the alert's origin). Empty when the call is exempt from auth (preflight),
	// which keeps a single empty-string series rather than dropping the metric.
	clusterID := ""
	if ident, ok := auth.FromContext(ctx); ok && ident != nil {
		clusterID = ident.ClusterID
	}

	auditID := e.auditInput(ctx, prompt, name, model)

	instruction := prompt
	var lastErr error
	for attempt := 0; attempt <= e.maxRetries; attempt++ {
		raw, u, err := e.provider.complete(ctx, instruction)
		if err != nil {
			// Transport error after the provider's own retries — not fixable by
			// a corrective prompt. Degrade to raw delivery.
			metrics.LLMCalls.WithLabelValues("error", name, model, clusterID).Inc()
			metrics.LLMCallDuration.WithLabelValues(name, model, clusterID).Observe(time.Since(start).Seconds())
			return nil, fmt.Errorf("%s call failed: %w", name, err)
		}

		metrics.LLMTokens.WithLabelValues("input", name, model, clusterID).Add(float64(u.input))
		metrics.LLMTokens.WithLabelValues("output", name, model, clusterID).Add(float64(u.output))

		analysis, verr := decodeAndValidate(raw)
		if verr == nil {
			e.auditOutput(auditID, raw, u, name, model)
			metrics.LLMCalls.WithLabelValues("ok", name, model, clusterID).Inc()
			metrics.LLMCallDuration.WithLabelValues(name, model, clusterID).Observe(time.Since(start).Seconds())
			return analysis, nil
		}

		lastErr = verr
		metrics.LLMValidationFailures.WithLabelValues(name, model, clusterID).Inc()
		e.logger.Warn("LLM output failed schema validation",
			zap.String("provider", name),
			zap.String("model", model),
			zap.Int("attempt", attempt+1),
			zap.Error(verr),
		)

		if attempt < e.maxRetries {
			metrics.LLMRetries.WithLabelValues(name, model, clusterID).Inc()
			// Append correction to the User part — System rules stay intact so
			// the correction can't be mistaken for an attacker-crafted override.
			instruction = Prompt{System: prompt.System, User: prompt.User + correctiveSuffix(verr)}
		}
	}

	// Retries exhausted: degrade honestly rather than loosely parse. The final
	// validation failure was already counted inside the loop above.
	metrics.LLMDegraded.WithLabelValues(name, model, clusterID).Inc()
	metrics.LLMCalls.WithLabelValues("error", name, model, clusterID).Inc()
	metrics.LLMCallDuration.WithLabelValues(name, model, clusterID).Observe(time.Since(start).Seconds())
	e.logger.Error("LLM output invalid after retries, degrading to raw delivery",
		zap.String("provider", name),
		zap.String("model", model),
		zap.Error(lastErr),
	)
	return nil, fmt.Errorf("%w: %v", ErrDegraded, lastErr)
}

// auditInput emits a structured audit record of the prompt that will be sent
// to the LLM. Required for GDPR/ISO style audits ("what did the model see?")
// and for incident-response forensics on a misbehaving analysis. The log
// always carries the caller's verified mTLS identity (cluster_id, tenant_id,
// cert serial) and the SHA-256 of the prompt for tamper-evidence cross-checks;
// the prompt body is included only when auditMode==AuditFull. AuditOff returns
// an empty ID and emits nothing — the loop still runs unchanged. Prompts are
// already redacted upstream by the collector, so the full mode does not
// re-introduce PII; it only inflates log volume.
func (e *Evaluator) auditInput(ctx context.Context, prompt Prompt, provider, model string) string {
	if e.auditMode == AuditOff {
		return ""
	}
	sysSum := sha256.Sum256([]byte(prompt.System))
	usrSum := sha256.Sum256([]byte(prompt.User))
	// audit_id derives from the combined hash so input/output records pair up
	// cleanly even if the same User text is sent under a rotated System prompt.
	combined := sha256.Sum256(append(sysSum[:], usrSum[:]...))
	id := hex.EncodeToString(combined[:8])
	fields := []zap.Field{
		zap.Bool("audit", true),
		zap.String("audit_phase", "llm_input"),
		zap.String("audit_id", id),
		zap.String("provider", provider),
		zap.String("model", model),
		zap.String("system_sha256", hex.EncodeToString(sysSum[:])),
		zap.String("user_sha256", hex.EncodeToString(usrSum[:])),
		zap.Int("system_bytes", len(prompt.System)),
		zap.Int("user_bytes", len(prompt.User)),
	}
	if e.auditMode == AuditFull {
		fields = append(fields,
			zap.String("system", prompt.System),
			zap.String("user", prompt.User),
		)
	}
	if ident, ok := auth.FromContext(ctx); ok && ident != nil {
		fields = append(fields,
			zap.String("tenant_id", ident.TenantID),
			zap.String("cluster_id", ident.ClusterID),
			zap.String("cert_serial", ident.SerialNumber),
		)
	}
	e.logger.Info("llm input audit", fields...)
	return id
}

// auditOutput emits the matching output side of the audit record. Skipped
// when auditMode==AuditOff (the caller passes the empty auditID from
// auditInput); body included only in AuditFull.
func (e *Evaluator) auditOutput(auditID string, raw json.RawMessage, u usage, provider, model string) {
	if e.auditMode == AuditOff || auditID == "" {
		return
	}
	sum := sha256.Sum256(raw)
	fields := []zap.Field{
		zap.Bool("audit", true),
		zap.String("audit_phase", "llm_output"),
		zap.String("audit_id", auditID),
		zap.String("provider", provider),
		zap.String("model", model),
		zap.String("output_sha256", hex.EncodeToString(sum[:])),
		zap.Int("output_bytes", len(raw)),
		zap.Int("input_tokens", u.input),
		zap.Int("output_tokens", u.output),
	}
	if e.auditMode == AuditFull {
		fields = append(fields, zap.ByteString("output", raw))
	}
	e.logger.Info("llm output audit", fields...)
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
