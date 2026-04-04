package silence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur-central/proto"
)

type Client struct {
	baseURL  string
	duration time.Duration
	enabled  bool
	client   *http.Client
	logger   *zap.Logger
}

func NewClient(baseURL string, duration time.Duration, enabled bool, logger *zap.Logger) *Client {
	return &Client{
		baseURL:  baseURL,
		duration: duration,
		enabled:  enabled,
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
		return fmt.Errorf("alertmanager API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("alertmanager API returned %d", resp.StatusCode)
	}

	c.logger.Info("created AlertManager silence",
		zap.String("alert", payload.AlertName),
		zap.String("namespace", payload.Namespace),
		zap.String("reason", reason),
		zap.Duration("duration", c.duration),
	)

	return nil
}
