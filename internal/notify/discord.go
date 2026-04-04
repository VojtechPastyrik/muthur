package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Discord struct {
	name       string
	webhookURL string
	client     *http.Client
}

func newDiscord(name string, cfg map[string]string) (Notifier, error) {
	url := cfg["webhook_url"]
	if url == "" {
		return nil, fmt.Errorf("discord: webhook_url is required")
	}
	return &Discord{
		name:       name,
		webhookURL: url,
		client:     &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (d *Discord) Name() string { return d.name }

func (d *Discord) Send(ctx context.Context, msg *Message) error {
	body := map[string]string{
		"content": msg.Text,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create discord request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("discord API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discord API returned %d", resp.StatusCode)
	}

	return nil
}
