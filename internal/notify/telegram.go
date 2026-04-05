package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Telegram struct {
	name   string
	token  string
	chatID string
	client *http.Client
}

func newTelegram(name string, cfg map[string]string) (Notifier, error) {
	token := cfg["token"]
	chatID := cfg["chat_id"]
	if token == "" {
		return nil, fmt.Errorf("telegram: token is required")
	}
	if chatID == "" {
		return nil, fmt.Errorf("telegram: chat_id is required")
	}
	return &Telegram{
		name:   name,
		token:  token,
		chatID: chatID,
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (t *Telegram) Name() string { return t.name }

type telegramSendMessage struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

func (t *Telegram) Send(ctx context.Context, msg *Message) error {
	body := telegramSendMessage{
		ChatID:                t.chatID,
		Text:                  buildTelegramHTML(msg),
		ParseMode:             "HTML",
		DisableWebPagePreview: true,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned %d", resp.StatusCode)
	}

	return nil
}

// buildTelegramHTML renders the alert using Telegram's HTML parse mode.
// Only <b>, <i>, <code>, <pre>, and <a href> tags are used — all user-supplied
// text is escaped so the bot API accepts it regardless of content.
func buildTelegramHTML(msg *Message) string {
	var b strings.Builder
	p := msg.Payload
	if p == nil {
		return ""
	}

	// Header — [SEVERITY] cluster / alert
	b.WriteString("<b>")
	b.WriteString(tgEscape(msg.Title()))
	b.WriteString("</b>\n\n")

	// Structural block
	if p.Namespace != "" {
		b.WriteString("<b>Namespace:</b> <code>")
		b.WriteString(tgEscape(p.Namespace))
		b.WriteString("</code>\n")
	}
	if tl := targetLine(p); tl != "" {
		b.WriteString("<b>Target:</b> <code>")
		b.WriteString(tgEscape(tl))
		b.WriteString("</code>\n")
	}
	if r := restartInfo(p); r != "" {
		b.WriteString("<b>Pod state:</b> ")
		b.WriteString(tgEscape(r))
		b.WriteString("\n")
	}

	// AI analysis (firing only)
	if !msg.Resolved() && msg.Analysis != nil {
		if msg.Analysis.RootCause != "" {
			b.WriteString("\n<b>Root cause:</b> ")
			b.WriteString(tgEscape(msg.Analysis.RootCause))
			b.WriteString("\n")
		}
		if msg.Analysis.Evidence != "" {
			b.WriteString("<b>Evidence:</b> ")
			b.WriteString(tgEscape(msg.Analysis.Evidence))
			b.WriteString("\n")
		}
		if msg.Analysis.Action != "" {
			b.WriteString("<b>Action:</b> ")
			b.WriteString(tgEscape(msg.Analysis.Action))
			b.WriteString("\n")
		}
	} else if msg.Resolved() {
		b.WriteString("\n<i>Alert has cleared.</i>\n")
	} else if p.Summary != "" {
		b.WriteString("\n")
		b.WriteString(tgEscape(p.Summary))
		b.WriteString("\n")
	}

	// Grafana link
	if msg.GrafanaURL != "" {
		b.WriteString("\n<a href=\"")
		b.WriteString(tgEscapeAttr(msg.GrafanaURL))
		b.WriteString("\">Open in Grafana</a>")
	}

	return b.String()
}

// tgEscape escapes the three characters Telegram HTML parse mode is strict
// about when they appear outside of tags: &, <, >.
func tgEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
	)
	return r.Replace(s)
}

// tgEscapeAttr escapes characters for use inside an HTML attribute value.
func tgEscapeAttr(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
	)
	return r.Replace(s)
}
