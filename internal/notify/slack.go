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

// Slack attachment colors (hex). Using attachments + blocks gives us both
// the coloured left bar (Prometheus-style) and Block Kit's rich layout.
const (
	slackColorCritical = "#E01E5A"
	slackColorWarning  = "#ECB22E"
	slackColorInfo     = "#36C5F0"
	slackColorResolved = "#2EB67D"
)

type slackPayload struct {
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type     string            `json:"type"`
	Text     *slackText        `json:"text,omitempty"`
	Fields   []slackText       `json:"fields,omitempty"`
	Elements []json.RawMessage `json:"elements,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (s *Slack) Send(ctx context.Context, msg *Message) error {
	payload := slackPayload{Attachments: []slackAttachment{buildSlackAttachment(msg)}}

	data, err := json.Marshal(payload)
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

func buildSlackAttachment(msg *Message) slackAttachment {
	color := slackColorInfo
	switch msg.Severity() {
	case "critical":
		color = slackColorCritical
	case "warning":
		color = slackColorWarning
	}
	if msg.Resolved() {
		color = slackColorResolved
	}

	p := msg.Payload
	blocks := []slackBlock{
		{
			Type: "header",
			Text: &slackText{Type: "plain_text", Text: truncate(msg.Title(), 150)},
		},
	}

	if p != nil {
		// Compact field grid — up to 10 two-column fields per section in Slack.
		fields := []slackText{
			{Type: "mrkdwn", Text: "*Cluster*\n" + safe(p.ClusterId)},
			{Type: "mrkdwn", Text: "*Severity*\n" + msg.Severity()},
		}
		if p.Namespace != "" {
			fields = append(fields, slackText{Type: "mrkdwn", Text: "*Namespace*\n" + p.Namespace})
		}
		if tl := targetLine(p); tl != "" {
			fields = append(fields, slackText{Type: "mrkdwn", Text: "*Target*\n" + tl})
		}
		if r := restartInfo(p); r != "" {
			fields = append(fields, slackText{Type: "mrkdwn", Text: "*Pod state*\n" + r})
		}
		blocks = append(blocks, slackBlock{Type: "section", Fields: fields})

		// Root cause / Evidence / Action
		if msg.Resolved() {
			blocks = append(blocks, slackBlock{
				Type: "section",
				Text: &slackText{Type: "mrkdwn", Text: "_Alert has cleared._"},
			})
		} else if msg.Analysis != nil {
			var body string
			if msg.Analysis.RootCause != "" {
				body += "*Root cause:* " + msg.Analysis.RootCause + "\n"
			}
			if msg.Analysis.Evidence != "" {
				body += "*Evidence:* " + msg.Analysis.Evidence + "\n"
			}
			if msg.Analysis.Action != "" {
				body += "*Action:* " + msg.Analysis.Action
			}
			if body != "" {
				blocks = append(blocks, slackBlock{
					Type: "section",
					Text: &slackText{Type: "mrkdwn", Text: truncate(body, 3000)},
				})
			}
		} else if p.Summary != "" {
			blocks = append(blocks, slackBlock{
				Type: "section",
				Text: &slackText{Type: "mrkdwn", Text: truncate(p.Summary, 3000)},
			})
		}

		// Grafana link context
		if msg.GrafanaURL != "" {
			blocks = append(blocks, slackBlock{
				Type: "section",
				Text: &slackText{Type: "mrkdwn", Text: "<" + msg.GrafanaURL + "|Open in Grafana>"},
			})
		}

		// Footer with timestamp
		if p.FiredAt > 0 {
			ts := time.Unix(p.FiredAt, 0).UTC().Format(time.RFC3339)
			el, _ := json.Marshal(slackText{Type: "mrkdwn", Text: "Fired at " + ts})
			blocks = append(blocks, slackBlock{
				Type:     "context",
				Elements: []json.RawMessage{el},
			})
		}
	}

	return slackAttachment{Color: color, Blocks: blocks}
}
