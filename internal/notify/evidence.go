package notify

import (
	"fmt"
	"strconv"
	"strings"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

// EvidenceConfig controls how much raw evidence is attached to a notification.
type EvidenceConfig struct {
	Enabled  bool
	LogLines int // max redacted log lines to show (tail)
}

// maxEvidenceLogLineLen caps a single rendered evidence log line so one giant
// line can't blow past a channel's message limits. The logs are already
// redacted upstream; this is purely a display bound.
const maxEvidenceLogLineLen = 200

// AttachEvidence curates a tail of redacted logs and a few key metric facts from
// the payload and stores them on the message. No-op when disabled or when the
// payload carries nothing useful. The data is already redacted by the collector
// — this only selects and formats it.
func AttachEvidence(msg *Message, payload *pb.AlertPayload, cfg EvidenceConfig) {
	if msg == nil || payload == nil || !cfg.Enabled {
		return
	}
	msg.EvidenceLogs = evidenceLogs(payload, cfg.LogLines)
	msg.EvidenceMetrics = evidenceMetrics(payload)
}

// evidenceLogs returns the last n redacted log lines, each truncated.
func evidenceLogs(payload *pb.AlertPayload, n int) []string {
	if n <= 0 || len(payload.RedactedLogs) == 0 {
		return nil
	}
	lines := payload.RedactedLogs
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimRight(l, "\n\r\t ")
		if l == "" {
			continue
		}
		if len(l) > maxEvidenceLogLineLen {
			l = l[:maxEvidenceLogLineLen] + "…"
		}
		out = append(out, l)
	}
	return out
}

// evidenceMetrics distills the payload's metric series and pod metadata into a
// few short human-readable facts (latest value per series, restart count,
// memory limit). Capped so the section stays skimmable.
func evidenceMetrics(payload *pb.AlertPayload) []string {
	var facts []string

	for _, series := range payload.Metrics {
		if len(series.Points) == 0 {
			continue
		}
		last := series.Points[len(series.Points)-1].Value
		facts = append(facts, fmt.Sprintf("%s: %s", shortMetricName(series.MetricName), fmtMetricValue(series.Unit, last)))
		if len(facts) >= 4 {
			break
		}
	}

	// Pod-level facts that are often the crux (restarts, memory ceiling).
	for _, pm := range payload.PodMetas {
		if pm.RestartCount > 0 {
			facts = append(facts, fmt.Sprintf("restarts: %d", pm.RestartCount))
		}
		if pm.MemoryLimit != "" {
			facts = append(facts, "memory limit: "+pm.MemoryLimit)
		}
		if pm.Phase != "" && pm.Phase != "Running" {
			facts = append(facts, "phase: "+pm.Phase)
		}
		break // representative pod only
	}

	return facts
}

// shortMetricName strips the common container_/node_/kube_ prefixes for display.
func shortMetricName(name string) string {
	for _, p := range []string{"container_", "node_", "kube_", "kubelet_"} {
		if strings.HasPrefix(name, p) {
			return strings.TrimPrefix(name, p)
		}
	}
	return name
}

// fmtMetricValue renders a value with a unit-appropriate suffix.
func fmtMetricValue(unit string, v float64) string {
	switch unit {
	case "bytes":
		return humanBytes(v)
	case "percent":
		return strconv.FormatFloat(v, 'f', 1, 64) + "%"
	case "seconds":
		return strconv.FormatFloat(v, 'f', 2, 64) + "s"
	default: // count and anything else
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', 2, 64)
	}
}

func humanBytes(v float64) string {
	const unit = 1024.0
	if v < unit {
		return strconv.FormatFloat(v, 'f', 0, 64) + "B"
	}
	exp := 0
	val := v
	for val >= unit && exp < 4 {
		val /= unit
		exp++
	}
	return strconv.FormatFloat(val, 'f', 1, 64) + string("KMGT"[exp-1]) + "iB"
}
