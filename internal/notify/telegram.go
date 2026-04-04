package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

func (t *Telegram) Send(ctx context.Context, msg *Message) error {
	body := map[string]string{
		"chat_id": t.chatID,
		"text":    msg.Text,
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
