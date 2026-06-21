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

	// Incident, when non-nil, means Payload is the representative alert of a
	// correlated group; RelatedAlerts holds the others. Notifiers surface this
	// as a "related alerts" section so one incident = one notification.
	Incident *Incident

	// FeedbackUpURL / FeedbackDownURL, when set, are clickable links operators
	// use to mark the analysis useful or wrong. Empty when feedback links are
	// disabled (no public URL configured).
	FeedbackUpURL   string
	FeedbackDownURL string
}

// Incident groups the alerts that were correlated into a single notification.
type Incident struct {
	// Alerts is every alert in the group, including the representative.
	Alerts []*pb.AlertPayload
}

// IsIncident reports whether this message represents a correlated group of more
// than one alert.
func (m *Message) IsIncident() bool {
	return m.Incident != nil && len(m.Incident.Alerts) > 1
}

// RelatedSummaries returns one short line per alert in the incident other than
// the representative (e.g. "PodCrashLoop (ns: default)").
func (m *Message) RelatedSummaries() []string {
	if !m.IsIncident() {
		return nil
	}
	var out []string
	for _, a := range m.Incident.Alerts {
		if a == m.Payload {
			continue
		}
		line := a.AlertName
		if a.Namespace != "" {
			line += " (ns: " + a.Namespace + ")"
		}
		out = append(out, line)
	}
	return out
}

// ConfidenceLine renders the trust-calibration signal for the analysis, e.g.
// "high confidence · stated" — so on-call can tell a data-grounded root cause
// from a confident guess. Empty when the analysis carries no signal.
func (m *Message) ConfidenceLine() string {
	if m.Analysis == nil {
		return ""
	}
	conf, ground := m.Analysis.Confidence, m.Analysis.Grounding
	switch {
	case conf != "" && ground != "":
		return conf + " confidence · " + ground
	case conf != "":
		return conf + " confidence"
	default:
		return ground
	}
}

// HasFeedback reports whether feedback links are present.
func (m *Message) HasFeedback() bool {
	return m.FeedbackUpURL != "" && m.FeedbackDownURL != ""
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
