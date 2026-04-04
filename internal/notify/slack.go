package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Slack struct {
	name       string
	webhookURL string
	client     *http.Client
}

func newSlack(name string, cfg map[string]string) (Notifier, error) {
	url := cfg["webhook_url"]
	if url == "" {
		return nil, fmt.Errorf("slack: webhook_url is required")
	}
	return &Slack{
		name:       name,
		webhookURL: url,
		client:     &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (s *Slack) Name() string { return s.name }

func (s *Slack) Send(ctx context.Context, msg *Message) error {
	body := map[string]string{
		"text": msg.Text,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack API call: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(respBody) != "ok" {
		return fmt.Errorf("slack API returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
