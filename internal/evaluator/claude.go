package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

type Analysis struct {
	Severity      string `json:"severity"`
	RootCause     string `json:"root_cause"`
	Evidence      string `json:"evidence"`
	Action        string `json:"action"`
	Silence       bool   `json:"silence"`
	SilenceReason string `json:"silence_reason,omitempty"`
}

type Evaluator struct {
	client *anthropic.Client
	model  string
	logger *zap.Logger
}

func New(apiKey, model string, logger *zap.Logger) *Evaluator {
	client := anthropic.NewClient(option.WithAPIKey(apiKey))
	return &Evaluator{
		client: &client,
		model:  model,
		logger: logger,
	}
}

func (e *Evaluator) Evaluate(ctx context.Context, payload *pb.AlertPayload) (*Analysis, error) {
	prompt := buildPrompt(payload)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			e.logger.Warn("retrying Claude API call",
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
			)
			time.Sleep(backoff)
		}

		analysis, err := e.call(ctx, prompt)
		if err == nil {
			return analysis, nil
		}
		lastErr = err
		e.logger.Error("Claude API call failed",
			zap.Error(err),
			zap.Int("attempt", attempt+1),
		)
	}

	return nil, fmt.Errorf("Claude API failed after 3 attempts: %w", lastErr)
}

func (e *Evaluator) call(ctx context.Context, prompt string) (*Analysis, error) {
	message, err := e.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(e.model),
		MaxTokens: 1024,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("messages.new: %w", err)
	}

	if len(message.Content) == 0 {
		return nil, fmt.Errorf("empty response from Claude")
	}

	text := message.Content[0].Text
	if text == "" {
		return nil, fmt.Errorf("no text content in Claude response")
	}

	cleaned := stripJSONFences(text)

	var analysis Analysis
	if err := json.Unmarshal([]byte(cleaned), &analysis); err != nil {
		return nil, fmt.Errorf("failed to parse Claude response as JSON: %w (raw: %s)", err, text)
	}

	return &analysis, nil
}

// stripJSONFences removes markdown code fences (```json ... ``` or ``` ... ```)
// that Claude sometimes wraps around JSON output despite being told not to.
// Safe no-op when the text is already bare JSON.
func stripJSONFences(text string) string {
	s := strings.TrimSpace(text)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	// Drop opening fence line (```json, ```JSON, ``` etc.)
	if nl := strings.IndexByte(s, '\n'); nl >= 0 {
		s = s[nl+1:]
	} else {
		s = strings.TrimPrefix(s, "```")
	}
	// Drop closing fence
	if idx := strings.LastIndex(s, "```"); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}
