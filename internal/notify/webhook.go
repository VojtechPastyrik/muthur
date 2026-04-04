package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Webhook struct {
	name   string
	url    string
	client *http.Client
}

func newWebhook(name string, cfg map[string]string) (Notifier, error) {
	url := cfg["url"]
	if url == "" {
		return nil, fmt.Errorf("webhook: url is required")
	}
	return &Webhook{
		name:   name,
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (w *Webhook) Name() string { return w.name }

func (w *Webhook) Send(ctx context.Context, msg *Message) error {
	body := map[string]any{
		"text":       msg.Text,
		"severity":   msg.Severity,
		"cluster_id": msg.ClusterID,
		"alert_name": msg.AlertName,
		"namespace":  msg.Namespace,
		"pod_name":   msg.PodName,
		"grafana":    msg.GrafanaURL,
	}

	if msg.Analysis != nil {
		body["analysis"] = msg.Analysis
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}

	return nil
}
