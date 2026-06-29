package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"go.uber.org/zap"
)

// anthropicProvider is the native Anthropic backend. It forces a single
// tool-use call so the model emits validated tool input rather than free-form
// text wrapped in markdown fences — the structured-output mechanism MUTHUR was
// built on. This is the default and best-supported provider.
type anthropicProvider struct {
	client  *anthropic.Client
	mdl     string
	timeout time.Duration
	logger  *zap.Logger
}

func newAnthropicProvider(apiKey, model string, perCallTimeout time.Duration, logger *zap.Logger) *anthropicProvider {
	client := anthropic.NewClient(option.WithAPIKey(apiKey))
	return &anthropicProvider{
		client:  &client,
		mdl:     model,
		timeout: perCallTimeout,
		logger:  logger,
	}
}

func (p *anthropicProvider) name() string  { return "anthropic" }
func (p *anthropicProvider) model() string { return p.mdl }

// structured is always true: Anthropic forced tool-use guarantees the model's
// output conforms to the tool input schema before it reaches us.
func (p *anthropicProvider) structured() bool { return true }

// analysisTool forces Claude to return its verdict as validated tool input
// rather than free-form text. The schema is sourced from the canonical
// definitions in schema.go so it can never drift from the OpenAI provider's.
func analysisTool() anthropic.ToolParam {
	return anthropic.ToolParam{
		Name:        "report_analysis",
		Description: anthropic.String("Report the structured analysis of the Kubernetes alert or incident. Always call this exactly once."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: analysisProperties(),
			Required:   analysisRequired(),
		},
	}
}

// complete sends the prompt with forced tool-use and returns the raw tool
// input. Transport-level retries (network/transient failures) are handled here
// with the same exponential backoff as the original implementation; schema
// validation and corrective retries live in the shared Evaluator.run.
//
// The prompt is delivered as a structural system/user split: System carries
// the analysis rules + anti-injection guidance via Anthropic's native System
// parameter, User carries the fenced alert data as the only user-role
// message. Together with the textual <untrusted_alert_data> fence in User,
// this gives two layers of separation between attacker-controlled log text
// and the rules that govern the model's verdict.
func (p *anthropicProvider) complete(ctx context.Context, prompt Prompt) (json.RawMessage, usage, error) {
	// Bound each attempt independently so a single stalled connection can't
	// consume the entire pipeline deadline — the LLM enriches, it must never
	// hold a page hostage.
	if p.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	tool := analysisTool()

	var systemBlocks []anthropic.TextBlockParam
	if prompt.System != "" {
		systemBlocks = []anthropic.TextBlockParam{{Text: prompt.System}}
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			p.logger.Warn("retrying Anthropic API call",
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
			)
			select {
			case <-ctx.Done():
				return nil, usage{}, ctx.Err()
			case <-time.After(backoff):
			}
		}

		message, err := p.client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     anthropic.Model(p.mdl),
			MaxTokens: 1024,
			System:    systemBlocks,
			Tools:     []anthropic.ToolUnionParam{{OfTool: &tool}},
			// Force the model to emit the structured tool call rather than prose.
			ToolChoice: anthropic.ToolChoiceParamOfTool(tool.Name),
			Messages: []anthropic.MessageParam{
				anthropic.NewUserMessage(anthropic.NewTextBlock(prompt.User)),
			},
		})
		if err != nil {
			lastErr = fmt.Errorf("messages.new: %w", err)
			p.logger.Error("Anthropic API call failed", zap.Error(err), zap.Int("attempt", attempt+1))
			continue
		}

		u := usage{input: int(message.Usage.InputTokens), output: int(message.Usage.OutputTokens)}

		for _, block := range message.Content {
			if tu, ok := block.AsAny().(anthropic.ToolUseBlock); ok && tu.Name == tool.Name {
				return json.RawMessage(tu.Input), u, nil
			}
		}
		// A forced tool call with no tool block is a contract violation by the
		// API, not a transient fault — fail without burning more retries.
		return nil, u, fmt.Errorf("Anthropic returned no %s tool call", tool.Name)
	}

	return nil, usage{}, fmt.Errorf("Anthropic API failed after 3 attempts: %w", lastErr)
}
