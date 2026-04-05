package notify

import (
	"context"

	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

type Notifier interface {
	Name() string
	Send(ctx context.Context, msg *Message) error
}

// Message is the structured payload passed to every notifier. Each notifier
// builds its own channel-specific representation from these fields — there is
// no longer a pre-rendered text blob, because plain text wastes the rich
// formatting capabilities of Discord, Slack, and Telegram.
type Message struct {
	Payload    *pb.AlertPayload
	Analysis   *evaluator.Analysis
	GrafanaURL string
}

// Resolved reports whether the underlying alert is a resolved notification.
func (m *Message) Resolved() bool {
	return m.Payload != nil && m.Payload.Status == "resolved"
}

// Severity returns a normalised severity, lowercased.
func (m *Message) Severity() string {
	if m.Payload == nil {
		return "info"
	}
	switch m.Payload.Severity {
	case "critical", "warning", "info":
		return m.Payload.Severity
	default:
		return "info"
	}
}

// Title composes the human-readable alert title used by rich notifiers.
func (m *Message) Title() string {
	if m.Payload == nil {
		return ""
	}
	prefix := "[" + upper(m.Severity()) + "]"
	if m.Resolved() {
		prefix = "[RESOLVED]"
	}
	return prefix + " " + m.Payload.ClusterId + " / " + m.Payload.AlertName
}

func upper(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		b[i] = c
	}
	return string(b)
}
