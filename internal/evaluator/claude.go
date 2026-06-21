package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/metrics"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// Analysis is the structured verdict Claude returns for an alert or incident.
type Analysis struct {
	Severity  string `json:"severity"`
	RootCause string `json:"root_cause"`
	Evidence  string `json:"evidence"`
	Action    string `json:"action"`
	// Confidence is Claude's self-assessed certainty in the root cause:
	// "high", "medium", or "low". Surfaced in notifications so on-call can
	// calibrate trust instead of treating every verdict as equally sure.
	Confidence string `json:"confidence"`
	// Grounding is "stated" when the root cause is read directly from the
	// provided logs/metrics, or "inferred" when Claude is reasoning beyond
	// what the data literally says. Separates observation from speculation.
	Grounding     string `json:"grounding"`
	Silence       bool   `json:"silence"`
	SilenceReason string `json:"silence_reason,omitempty"`
}

// Example is a past analysis with an operator verdict, fed back to Claude as a
// few-shot signal so evaluations improve per-cluster over time. Defined here
// (rather than in the feedback package) so evaluator has no dependency on
// feedback — the dependency runs the other way.
type Example struct {
	AlertName string
	Verdict   string // "useful" or "wrong"
	Analysis  *Analysis
}

type Evaluator struct {
	client  *anthropic.Client
	model   string
	timeout time.Duration
	logger  *zap.Logger
}

// New builds an Evaluator. perCallTimeout bounds each individual Claude API
// call so a hung connection fails fast and the pipeline falls back to raw
// alert delivery promptly, rather than tying up the whole pipeline deadline on
// a single stalled request. A non-positive value disables the per-call bound.
func New(apiKey, model string, perCallTimeout time.Duration, logger *zap.Logger) *Evaluator {
	client := anthropic.NewClient(option.WithAPIKey(apiKey))
	return &Evaluator{
		client:  &client,
		model:   model,
		timeout: perCallTimeout,
		logger:  logger,
	}
}

// analysisTool forces Claude to return its verdict as validated tool input
// rather than free-form text wrapped in markdown fences. This eliminates the
// JSON-parsing failure mode entirely — the SDK guarantees the input matches the
// schema before it reaches us.
func analysisTool() anthropic.ToolParam {
	return anthropic.ToolParam{
		Name:        "report_analysis",
		Description: anthropic.String("Report the structured analysis of the Kubernetes alert or incident. Always call this exactly once."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"severity": map[string]any{
					"type":        "string",
					"enum":        []string{"critical", "warning", "info"},
					"description": "Overall severity of the situation based on the evidence.",
				},
				"root_cause": map[string]any{
					"type":        "string",
					"description": "One sentence root cause grounded in the provided logs and metrics.",
				},
				"evidence": map[string]any{
					"type":        "string",
					"description": "Specific log lines or metric trends supporting the root cause.",
				},
				"action": map[string]any{
					"type":        "string",
					"description": "Recommended immediate action.",
				},
				"confidence": map[string]any{
					"type":        "string",
					"enum":        []string{"high", "medium", "low"},
					"description": "Your certainty in the root cause. 'high' only when the logs/metrics state it directly; 'low' when you are guessing from sparse data.",
				},
				"grounding": map[string]any{
					"type":        "string",
					"enum":        []string{"stated", "inferred"},
					"description": "'stated' if the root cause is read directly from the provided data; 'inferred' if you are reasoning beyond what the data literally says.",
				},
				"silence": map[string]any{
					"type":        "boolean",
					"description": "True only if this alert is noise that should be silenced.",
				},
				"silence_reason": map[string]any{
					"type":        "string",
					"description": "Why the alert should be silenced. Only set when silence is true.",
				},
			},
			Required: []string{"severity", "root_cause", "evidence", "action", "confidence", "grounding", "silence"},
		},
	}
}

// Evaluate analyses a single alert.
func (e *Evaluator) Evaluate(ctx context.Context, payload *pb.AlertPayload, examples []Example) (*Analysis, error) {
	return e.run(ctx, buildPrompt(payload, examples))
}

// EvaluateIncident analyses a group of correlated alerts as one incident,
// asking Claude for a single unified root cause spanning all of them.
func (e *Evaluator) EvaluateIncident(ctx context.Context, payloads []*pb.AlertPayload, examples []Example) (*Analysis, error) {
	return e.run(ctx, buildIncidentPrompt(payloads, examples))
}

func (e *Evaluator) run(ctx context.Context, prompt string) (*Analysis, error) {
	start := time.Now()

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			e.logger.Warn("retrying Claude API call",
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		analysis, err := e.call(ctx, prompt)
		if err == nil {
			metrics.LLMCalls.WithLabelValues("ok").Inc()
			metrics.LLMCallDuration.Observe(time.Since(start).Seconds())
			return analysis, nil
		}
		lastErr = err
		e.logger.Error("Claude API call failed",
			zap.Error(err),
			zap.Int("attempt", attempt+1),
		)
	}

	metrics.LLMCalls.WithLabelValues("error").Inc()
	metrics.LLMCallDuration.Observe(time.Since(start).Seconds())
	return nil, fmt.Errorf("Claude API failed after 3 attempts: %w", lastErr)
}

func (e *Evaluator) call(ctx context.Context, prompt string) (*Analysis, error) {
	// Bound each attempt independently so a single stalled connection can't
	// consume the entire pipeline deadline — the LLM enriches, it must never
	// hold a page hostage.
	if e.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	tool := analysisTool()
	message, err := e.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(e.model),
		MaxTokens: 1024,
		Tools:     []anthropic.ToolUnionParam{{OfTool: &tool}},
		// Force the model to emit the structured tool call rather than prose.
		ToolChoice: anthropic.ToolChoiceParamOfTool(tool.Name),
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("messages.new: %w", err)
	}

	metrics.LLMTokens.WithLabelValues("input").Add(float64(message.Usage.InputTokens))
	metrics.LLMTokens.WithLabelValues("output").Add(float64(message.Usage.OutputTokens))

	for _, block := range message.Content {
		if tu, ok := block.AsAny().(anthropic.ToolUseBlock); ok && tu.Name == tool.Name {
			var analysis Analysis
			if err := json.Unmarshal(tu.Input, &analysis); err != nil {
				return nil, fmt.Errorf("unmarshal tool input: %w", err)
			}
			return &analysis, nil
		}
	}
	return nil, fmt.Errorf("Claude returned no %s tool call", tool.Name)
}
