package notify

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
	"time"
)

// SMTP delivers notifications as plain-text email over STARTTLS (port 587 is the
// expected default). Auth is optional: when username is empty, no AUTH is
// attempted (internal relays). The password is supplied via the standard
// `password_file` secret convention resolved before this factory runs.
type SMTP struct {
	name string
	host string
	port string
	from string
	to   []string
	auth smtp.Auth
}

func newSMTP(name string, cfg map[string]string) (Notifier, error) {
	host := cfg["host"]
	if host == "" {
		return nil, fmt.Errorf("smtp: host is required")
	}
	from := cfg["from"]
	if from == "" {
		return nil, fmt.Errorf("smtp: from is required")
	}
	var to []string
	for _, addr := range strings.Split(cfg["to"], ",") {
		if addr = strings.TrimSpace(addr); addr != "" {
			to = append(to, addr)
		}
	}
	if len(to) == 0 {
		return nil, fmt.Errorf("smtp: at least one 'to' address is required")
	}
	port := cfg["port"]
	if port == "" {
		port = "587"
	}

	var auth smtp.Auth
	if user := cfg["username"]; user != "" {
		auth = smtp.PlainAuth("", user, cfg["password"], host)
	}

	return &SMTP{name: name, host: host, port: port, from: from, to: to, auth: auth}, nil
}

func (s *SMTP) Name() string { return s.name }

func (s *SMTP) Send(ctx context.Context, msg *Message) error {
	body := buildEmail(s.from, s.to, msg)
	addr := s.host + ":" + s.port

	// net/smtp.SendMail negotiates STARTTLS when the server advertises it and
	// applies auth only when non-nil. It is blocking, so honour ctx with a
	// deadline-bounded goroutine.
	done := make(chan error, 1)
	go func() {
		done <- smtp.SendMail(addr, s.auth, s.from, s.to, []byte(body))
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("smtp send cancelled: %w", ctx.Err())
	case err := <-done:
		if err != nil {
			return fmt.Errorf("smtp send: %w", err)
		}
		return nil
	}
}

// buildEmail renders the RFC 5322 message: headers + a readable plain-text body
// carrying the analysis and evidence.
func buildEmail(from string, to []string, msg *Message) string {
	var b strings.Builder

	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + msg.Title() + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")

	p := msg.Payload
	if p != nil {
		fmt.Fprintf(&b, "Cluster:   %s\r\n", p.ClusterId)
		fmt.Fprintf(&b, "Severity:  %s\r\n", msg.Severity())
		if p.Namespace != "" {
			fmt.Fprintf(&b, "Namespace: %s\r\n", p.Namespace)
		}
		if tl := targetLine(p); tl != "" {
			fmt.Fprintf(&b, "Target:    %s\r\n", tl)
		}
	}

	if msg.Resolved() {
		b.WriteString("\r\nAlert has cleared.\r\n")
		return b.String()
	}

	if a := msg.Analysis; a != nil {
		b.WriteString("\r\n")
		if a.RootCause != "" {
			fmt.Fprintf(&b, "Root cause: %s\r\n", a.RootCause)
		}
		if a.Evidence != "" {
			fmt.Fprintf(&b, "Evidence:   %s\r\n", a.Evidence)
		}
		if a.Action != "" {
			fmt.Fprintf(&b, "Action:     %s\r\n", a.Action)
		}
		if cl := msg.ConfidenceLine(); cl != "" {
			fmt.Fprintf(&b, "Confidence: %s\r\n", cl)
		}
	} else if p != nil && p.Summary != "" {
		fmt.Fprintf(&b, "\r\n%s\r\n", p.Summary)
	}

	if msg.HasEvidence() {
		b.WriteString("\r\n--- Evidence ---\r\n")
		if len(msg.EvidenceMetrics) > 0 {
			b.WriteString(strings.Join(msg.EvidenceMetrics, "  ·  ") + "\r\n")
		}
		for _, line := range msg.EvidenceLogs {
			b.WriteString("  " + line + "\r\n")
		}
	}

	if related := msg.RelatedSummaries(); len(related) > 0 {
		fmt.Fprintf(&b, "\r\nRelated alerts (%d):\r\n", len(related))
		for _, r := range related {
			b.WriteString("  - " + r + "\r\n")
		}
	}

	if msg.GrafanaURL != "" {
		fmt.Fprintf(&b, "\r\nGrafana: %s\r\n", msg.GrafanaURL)
	}
	if msg.HasFeedback() {
		fmt.Fprintf(&b, "\r\nFeedback: useful %s | wrong %s\r\n", msg.FeedbackUpURL, msg.FeedbackDownURL)
	}

	return b.String()
}
