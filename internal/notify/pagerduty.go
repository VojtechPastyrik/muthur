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
	name       string
	routingKey string
	url        string
	client     *http.Client
}

func newPagerDuty(name string, cfg map[string]string) (Notifier, error) {
	key := cfg["routing_key"]
	if key == "" {
		return nil, fmt.Errorf("pagerduty: routing_key is required")
	}
	url := cfg["url"]
	if url == "" {
		url = pagerDutyDefaultURL
	}
	return &PagerDuty{
		name:       name,
		routingKey: key,
		url:        url,
		client:     &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (p *PagerDuty) Name() string { return p.name }

func (p *PagerDuty) Send(ctx context.Context, msg *Message) error {
	event := buildPagerDutyEvent(p.routingKey, msg)

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

func buildPagerDutyEvent(routingKey string, msg *Message) map[string]any {
	p := msg.Payload
	dedupKey := fmt.Sprintf("muthur-%s-%s-%s",
		safeField(p, "cluster"),
		safeField(p, "alert"),
		safeField(p, "namespace"),
	)

	// Resolve events need only routing_key, event_action, and dedup_key —
	// everything else is ignored by the Events API v2.
	if msg.Resolved() {
		return map[string]any{
			"routing_key":  routingKey,
			"event_action": "resolve",
			"dedup_key":    dedupKey,
		}
	}

	severity := msg.Severity()
	if severity != "critical" && severity != "warning" && severity != "info" {
		severity = "info"
	}

	summary := ""
	if p != nil {
		summary = p.AlertName
		if p.Summary != "" {
			summary = p.AlertName + ": " + p.Summary
		}
	}
	summary = truncate(summary, 1024) // Events API v2 summary cap

	customDetails := map[string]any{}
	if p != nil {
		customDetails["namespace"] = p.Namespace
		customDetails["pod"] = p.PodName
		customDetails["target"] = targetLine(p)
		customDetails["fired_at"] = time.Unix(p.FiredAt, 0).UTC().Format(time.RFC3339)
		if p.Description != "" {
			customDetails["description"] = p.Description
		}
	}
	if msg.Analysis != nil {
		customDetails["root_cause"] = msg.Analysis.RootCause
		customDetails["evidence"] = msg.Analysis.Evidence
		customDetails["recommended_action"] = msg.Analysis.Action
	}
	if msg.GrafanaURL != "" {
		customDetails["grafana"] = msg.GrafanaURL
	}

	event := map[string]any{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"dedup_key":    dedupKey,
		"payload": map[string]any{
			"summary":        summary,
			"source":         safeField(p, "cluster"),
			"severity":       severity,
			"component":      safeField(p, "pod"),
			"group":          safeField(p, "namespace"),
			"class":          safeField(p, "alert"),
			"custom_details": customDetails,
		},
	}
	if p != nil && p.FiredAt > 0 {
		event["payload"].(map[string]any)["timestamp"] =
			time.Unix(p.FiredAt, 0).UTC().Format(time.RFC3339)
	}
	if msg.GrafanaURL != "" {
		event["links"] = []map[string]string{
			{"href": msg.GrafanaURL, "text": "Grafana"},
		}
	}
	return event
}

func safeField(p any, which string) string {
	type payload interface {
		GetClusterId() string
		GetAlertName() string
		GetNamespace() string
		GetPodName() string
	}
	pp, ok := p.(payload)
	if !ok || pp == nil {
		return "unknown"
	}
	switch which {
	case "cluster":
		if v := pp.GetClusterId(); v != "" {
			return v
		}
	case "alert":
		if v := pp.GetAlertName(); v != "" {
			return v
		}
	case "namespace":
		if v := pp.GetNamespace(); v != "" {
			return v
		}
	case "pod":
		if v := pp.GetPodName(); v != "" {
			return v
		}
	}
	return "unknown"
}
