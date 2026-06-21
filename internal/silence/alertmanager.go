package silence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur/internal/metrics"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

type Client struct {
	baseURL  string
	duration time.Duration
	enabled  bool
	// allowed, when non-empty, is the set of alertnames that may ever be
	// auto-silenced. Empty means "no alertname restriction" — but critical
	// alerts are refused regardless (see CreateSilence).
	allowed map[string]bool
	client  *http.Client
	logger  *zap.Logger
}

// NewClient builds a silence client. allowlist is the set of alertnames the
// LLM is permitted to auto-silence; an empty/nil allowlist imposes no alertname
// restriction. Critical-severity alerts are NEVER silenced, regardless of
// allowlist or the model's request — this is the hard guard against a
// prompt-injected log line steering Claude into silencing a real page.
func NewClient(baseURL string, duration time.Duration, enabled bool, allowlist []string, logger *zap.Logger) *Client {
	var allowed map[string]bool
	if len(allowlist) > 0 {
		allowed = make(map[string]bool, len(allowlist))
		for _, name := range allowlist {
			if name = strings.TrimSpace(name); name != "" {
				allowed[name] = true
			}
		}
	}
	return &Client{
		baseURL:  baseURL,
		duration: duration,
		enabled:  enabled,
		allowed:  allowed,
		client:   &http.Client{Timeout: 10 * time.Second},
		logger:   logger,
	}
}

type matcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"isRegex"`
	IsEqual bool   `json:"isEqual"`
}

type silenceRequest struct {
	Matchers  []matcher `json:"matchers"`
	StartsAt  string    `json:"startsAt"`
	EndsAt    string    `json:"endsAt"`
	CreatedBy string    `json:"createdBy"`
	Comment   string    `json:"comment"`
}

func (c *Client) CreateSilence(ctx context.Context, payload *pb.AlertPayload, reason string) error {
	if !c.enabled {
		return nil
	}

	// Hard guard: never auto-silence a critical alert. The silence decision
	// originates from Claude reading attacker-influenceable log/pod content, so
	// a crafted log line must not be able to mute a real page. This rule lives
	// in code, not in the prompt, precisely because the prompt is the thing
	// being attacked.
	if strings.EqualFold(payload.Severity, "critical") {
		metrics.Silences.WithLabelValues("blocked").Inc()
		c.logger.Warn("refusing to auto-silence critical alert",
			zap.String("alert", payload.AlertName),
			zap.String("namespace", payload.Namespace),
			zap.String("reason", reason),
		)
		return nil
	}

	// Allowlist guard: if configured, only named alerts may be silenced.
	if c.allowed != nil && !c.allowed[payload.AlertName] {
		metrics.Silences.WithLabelValues("blocked").Inc()
		c.logger.Warn("refusing to auto-silence alert not on allowlist",
			zap.String("alert", payload.AlertName),
			zap.String("namespace", payload.Namespace),
			zap.String("reason", reason),
		)
		return nil
	}

	now := time.Now().UTC()
	req := silenceRequest{
		Matchers: []matcher{
			{Name: "alertname", Value: payload.AlertName, IsRegex: false, IsEqual: true},
			{Name: "namespace", Value: payload.Namespace, IsRegex: false, IsEqual: true},
		},
		StartsAt:  now.Format(time.RFC3339),
		EndsAt:    now.Add(c.duration).Format(time.RFC3339),
		CreatedBy: "muthur-central",
		Comment:   reason,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal silence request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v2/silences", c.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create silence request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		metrics.Silences.WithLabelValues("error").Inc()
		return fmt.Errorf("alertmanager API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		metrics.Silences.WithLabelValues("error").Inc()
		return fmt.Errorf("alertmanager API returned %d", resp.StatusCode)
	}

	metrics.Silences.WithLabelValues("created").Inc()
	c.logger.Info("created AlertManager silence",
		zap.String("alert", payload.AlertName),
		zap.String("namespace", payload.Namespace),
		zap.String("reason", reason),
		zap.Duration("duration", c.duration),
	)

	return nil
}
