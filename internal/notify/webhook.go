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

type webhookPayload struct {
	Status      string         `json:"status"`
	Severity    string         `json:"severity"`
	ClusterID   string         `json:"cluster_id"`
	AlertName   string         `json:"alert_name"`
	Namespace   string         `json:"namespace"`
	Pod         string         `json:"pod,omitempty"`
	Target      string         `json:"target,omitempty"`
	Summary     string         `json:"summary,omitempty"`
	Description string         `json:"description,omitempty"`
	FiredAt     string         `json:"fired_at,omitempty"`
	GrafanaURL  string         `json:"grafana_url,omitempty"`
	Analysis    *webhookAI     `json:"analysis,omitempty"`
	Labels      map[string]any `json:"labels,omitempty"`
}

type webhookAI struct {
	RootCause string `json:"root_cause,omitempty"`
	Evidence  string `json:"evidence,omitempty"`
	Action    string `json:"action,omitempty"`
	Silence   bool   `json:"silence,omitempty"`
}

func (w *Webhook) Send(ctx context.Context, msg *Message) error {
	body := buildWebhookPayload(msg)

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

func buildWebhookPayload(msg *Message) webhookPayload {
	wp := webhookPayload{
		Status:     "firing",
		Severity:   msg.Severity(),
		GrafanaURL: msg.GrafanaURL,
	}
	if msg.Resolved() {
		wp.Status = "resolved"
	}
	if p := msg.Payload; p != nil {
		wp.ClusterID = p.ClusterId
		wp.AlertName = p.AlertName
		wp.Namespace = p.Namespace
		wp.Pod = p.PodName
		wp.Target = targetLine(p)
		wp.Summary = p.Summary
		wp.Description = p.Description
		if p.FiredAt > 0 {
			wp.FiredAt = time.Unix(p.FiredAt, 0).UTC().Format(time.RFC3339)
		}
		if len(p.Labels) > 0 {
			wp.Labels = make(map[string]any, len(p.Labels))
			for _, l := range p.Labels {
				wp.Labels[l.Name] = l.Value
			}
		}
	}
	if msg.Analysis != nil {
		wp.Analysis = &webhookAI{
			RootCause: msg.Analysis.RootCause,
			Evidence:  msg.Analysis.Evidence,
			Action:    msg.Analysis.Action,
			Silence:   msg.Analysis.Silence,
		}
	}
	return wp
}
