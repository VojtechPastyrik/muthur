package notify

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func writeSecretFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBuildReceivers_MultipleDiscord(t *testing.T) {
	opsFile := writeSecretFile(t, "https://discord.com/webhook/ops")
	devFile := writeSecretFile(t, "https://discord.com/webhook/dev")

	configs := []ReceiverConfig{
		{
			Name: "ops-discord",
			Type: "discord",
			Config: map[string]string{
				"webhook_url_file": opsFile,
			},
		},
		{
			Name: "dev-discord",
			Type: "discord",
			Config: map[string]string{
				"webhook_url_file": devFile,
			},
		},
	}

	receivers, err := BuildReceivers(configs, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receivers) != 2 {
		t.Fatalf("expected 2 receivers, got %d", len(receivers))
	}

	ops, ok := receivers["ops-discord"].(*Discord)
	if !ok {
		t.Fatal("expected Discord type for ops-discord")
	}
	if ops.webhookURL != "https://discord.com/webhook/ops" {
		t.Errorf("ops webhook_url not loaded from file, got: %q", ops.webhookURL)
	}

	dev, ok := receivers["dev-discord"].(*Discord)
	if !ok {
		t.Fatal("expected Discord type for dev-discord")
	}
	if dev.webhookURL != "https://discord.com/webhook/dev" {
		t.Errorf("dev webhook_url not loaded from file, got: %q", dev.webhookURL)
	}
}

func TestBuildReceivers_LiteralAndFileMixed(t *testing.T) {
	tokenFile := writeSecretFile(t, "bot-token-123")

	configs := []ReceiverConfig{
		{
			Name: "ops-telegram",
			Type: "telegram",
			Config: map[string]string{
				"token_file": tokenFile,
				"chat_id":    "-100123456",
			},
		},
	}

	receivers, err := BuildReceivers(configs, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tg, ok := receivers["ops-telegram"].(*Telegram)
	if !ok {
		t.Fatal("expected Telegram receiver")
	}
	if tg.token != "bot-token-123" {
		t.Errorf("token not loaded from file, got: %q", tg.token)
	}
	if tg.chatID != "-100123456" {
		t.Errorf("chat_id literal not preserved, got: %q", tg.chatID)
	}
}

func TestBuildReceivers_TrailingWhitespaceTrimmed(t *testing.T) {
	// Files often have trailing newlines — e.g. when kubectl mounts a Secret key.
	tokenFile := writeSecretFile(t, "my-secret-token\n")

	configs := []ReceiverConfig{
		{
			Name:   "wh",
			Type:   "webhook",
			Config: map[string]string{"url_file": tokenFile},
		},
	}

	receivers, err := BuildReceivers(configs, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	w := receivers["wh"].(*Webhook)
	if w.url != "my-secret-token" {
		t.Errorf("trailing whitespace not trimmed, got: %q", w.url)
	}
}

func TestBuildReceivers_MissingFileIsSkipped(t *testing.T) {
	// A missing secret file should skip the receiver, not crash.
	configs := []ReceiverConfig{
		{
			Name: "bad",
			Type: "discord",
			Config: map[string]string{
				"webhook_url_file": "/nonexistent/path/secret",
			},
		},
		{
			Name:   "good",
			Type:   "webhook",
			Config: map[string]string{"url": "https://example.com"},
		},
	}

	receivers, err := BuildReceivers(configs, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receivers) != 1 {
		t.Errorf("expected 1 receiver (missing file skipped), got %d", len(receivers))
	}
	if _, ok := receivers["good"]; !ok {
		t.Error("good receiver missing")
	}
	if _, ok := receivers["bad"]; ok {
		t.Error("bad receiver should have been skipped")
	}
}

func TestBuildReceivers_UnknownTypeSkipped(t *testing.T) {
	configs := []ReceiverConfig{
		{Name: "valid", Type: "discord", Config: map[string]string{"webhook_url": "x"}},
		{Name: "unknown", Type: "fax", Config: map[string]string{}},
	}

	receivers, err := BuildReceivers(configs, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receivers) != 1 {
		t.Errorf("expected 1 receiver (unknown type skipped), got %d", len(receivers))
	}
}

func TestBuildReceivers_DuplicateNameError(t *testing.T) {
	configs := []ReceiverConfig{
		{Name: "dup", Type: "discord", Config: map[string]string{"webhook_url": "x"}},
		{Name: "dup", Type: "slack", Config: map[string]string{"webhook_url": "y"}},
	}

	_, err := BuildReceivers(configs, zap.NewNop())
	if err == nil {
		t.Error("expected duplicate name error")
	}
}

func TestBuildReceivers_InvalidConfigSkipped(t *testing.T) {
	configs := []ReceiverConfig{
		{Name: "no-token", Type: "telegram", Config: map[string]string{"chat_id": "123"}},
		{Name: "valid", Type: "discord", Config: map[string]string{"webhook_url": "x"}},
	}

	receivers, err := BuildReceivers(configs, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receivers) != 1 {
		t.Errorf("expected 1 receiver (invalid skipped), got %d", len(receivers))
	}
}

func TestBuildReceivers_AllTypesLiteral(t *testing.T) {
	// Non-secret use case — literal values work for all types.
	configs := []ReceiverConfig{
		{Name: "tg", Type: "telegram", Config: map[string]string{"token": "t", "chat_id": "c"}},
		{Name: "dc", Type: "discord", Config: map[string]string{"webhook_url": "d"}},
		{Name: "sl", Type: "slack", Config: map[string]string{"webhook_url": "s"}},
		{Name: "pd", Type: "pagerduty", Config: map[string]string{"routing_key": "k"}},
		{Name: "wh", Type: "webhook", Config: map[string]string{"url": "w"}},
	}

	receivers, err := BuildReceivers(configs, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(receivers) != 5 {
		t.Errorf("expected 5 receivers, got %d", len(receivers))
	}

	for _, name := range []string{"tg", "dc", "sl", "pd", "wh"} {
		n, ok := receivers[name]
		if !ok {
			t.Errorf("missing receiver: %s", name)
			continue
		}
		if n.Name() != name {
			t.Errorf("receiver %s has wrong Name(): %s", name, n.Name())
		}
	}
}
