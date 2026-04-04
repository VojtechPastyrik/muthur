package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const pagerDutyDefaultURL = "https://events.pagerduty.com/v2/enqueue"

type PagerDuty struct {
	routingKey string
	url        string
	client     *http.Client
}

func NewPagerDuty(routingKey string) *PagerDuty {
	return &PagerDuty{
		routingKey: routingKey,
		url:        pagerDutyDefaultURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *PagerDuty) Name() string { return "pagerduty" }

func (p *PagerDuty) Send(ctx context.Context, msg *Message) error {
	severity := msg.Severity
	switch severity {
	case "critical":
		severity = "critical"
	case "warning":
		severity = "warning"
	default:
		severity = "info"
	}

	event := map[string]any{
		"routing_key":  p.routingKey,
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("%s-%s-%s", msg.ClusterID, msg.AlertName, msg.Namespace),
		"payload": map[string]any{
			"summary":  msg.Text,
			"source":   msg.ClusterID,
			"severity": severity,
			"group":    msg.ClusterID,
			"class":    msg.AlertName,
			"custom_details": map[string]string{
				"namespace":  msg.Namespace,
				"pod":        msg.PodName,
				"grafana":    msg.GrafanaURL,
			},
		},
		"links": []map[string]string{
			{"href": msg.GrafanaURL, "text": "Grafana"},
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal pagerduty payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create pagerduty request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("pagerduty API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("pagerduty API returned %d", resp.StatusCode)
	}

	return nil
}
