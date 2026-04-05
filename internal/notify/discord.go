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

// Discord embed colors (decimal).
const (
	colorCritical = 0xED4245 // red
	colorWarning  = 0xFAA61A // orange
	colorInfo     = 0x5865F2 // blurple
	colorResolved = 0x57F287 // green
)

type discordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	URL         string              `json:"url,omitempty"`
	Color       int                 `json:"color"`
	Fields      []discordEmbedField `json:"fields,omitempty"`
	Footer      *discordEmbedFooter `json:"footer,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
}

type discordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type discordEmbedFooter struct {
	Text string `json:"text"`
}

type discordPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

func (d *Discord) Send(ctx context.Context, msg *Message) error {
	embed := buildDiscordEmbed(msg)
	payload := discordPayload{Embeds: []discordEmbed{embed}}

	data, err := json.Marshal(payload)
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

func buildDiscordEmbed(msg *Message) discordEmbed {
	color := colorInfo
	switch msg.Severity() {
	case "critical":
		color = colorCritical
	case "warning":
		color = colorWarning
	}
	if msg.Resolved() {
		color = colorResolved
	}

	embed := discordEmbed{
		Title: msg.Title(),
		Color: color,
		URL:   msg.GrafanaURL,
	}

	p := msg.Payload
	if p == nil {
		return embed
	}

	// Description — for firing alerts this is the AI root cause (when
	// present) or the alert summary. For resolved alerts a short line.
	if msg.Resolved() {
		embed.Description = "Alert has cleared."
	} else if msg.Analysis != nil && msg.Analysis.RootCause != "" {
		embed.Description = msg.Analysis.RootCause
	} else if p.Summary != "" {
		embed.Description = p.Summary
	}
	embed.Description = truncate(embed.Description, 4000)

	// Structural fields (always present — cluster, alert, target, namespace).
	fields := []discordEmbedField{
		{Name: "Cluster", Value: safe(p.ClusterId), Inline: true},
		{Name: "Severity", Value: safe(msg.Severity()), Inline: true},
	}
	if p.Namespace != "" {
		fields = append(fields, discordEmbedField{Name: "Namespace", Value: p.Namespace, Inline: true})
	}
	if tl := targetLine(p); tl != "" {
		fields = append(fields, discordEmbedField{Name: "Target", Value: tl, Inline: false})
	}
	if r := restartInfo(p); r != "" {
		fields = append(fields, discordEmbedField{Name: "Pod state", Value: r, Inline: true})
	}

	// AI fields — only when evaluation actually produced something.
	if !msg.Resolved() && msg.Analysis != nil {
		if msg.Analysis.Evidence != "" {
			fields = append(fields, discordEmbedField{
				Name:  "Evidence",
				Value: truncate(msg.Analysis.Evidence, 1024),
			})
		}
		if msg.Analysis.Action != "" {
			fields = append(fields, discordEmbedField{
				Name:  "Recommended action",
				Value: truncate(msg.Analysis.Action, 1024),
			})
		}
	}

	embed.Fields = fields

	if p.FiredAt > 0 {
		embed.Timestamp = time.Unix(p.FiredAt, 0).UTC().Format(time.RFC3339)
	}
	if msg.GrafanaURL != "" {
		embed.Footer = &discordEmbedFooter{Text: "Click title to open in Grafana"}
	}

	return embed
}

// truncate trims a string to n runes, appending an ellipsis if cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func safe(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
