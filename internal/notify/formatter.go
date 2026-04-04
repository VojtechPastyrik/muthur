package notify

import (
	"fmt"
	"net/url"
	"strings"

	pb "github.com/VojtechPastyrik/muthur-central/proto"
	"github.com/VojtechPastyrik/muthur-central/internal/evaluator"
)

func FormatMessage(payload *pb.AlertPayload, analysis *evaluator.Analysis, grafanaBaseURL string) *Message {
	var b strings.Builder

	severity := strings.ToUpper(payload.Severity)
	b.WriteString(fmt.Sprintf("[%s] %s / %s\n\n", severity, payload.ClusterId, payload.AlertName))

	if payload.Target != nil {
		t := payload.Target
		b.WriteString(fmt.Sprintf("Target:   %s", t.TargetType))
		if t.PodName != "" {
			b.WriteString(fmt.Sprintf(" / %s", t.PodName))
		}
		if t.Deployment != "" {
			b.WriteString(fmt.Sprintf(" / %s", t.Deployment))
		}
		b.WriteString("\n")
		if t.Node != "" {
			b.WriteString(fmt.Sprintf("Node:     %s\n", t.Node))
		}
	}

	for _, pm := range payload.PodMetas {
		if pm.RestartCount > 0 {
			b.WriteString(fmt.Sprintf("Restarts: %d\n", pm.RestartCount))
		}
		if pm.MemoryLimit != "" {
			b.WriteString(fmt.Sprintf("Memory:   request=%s limit=%s\n", pm.MemoryRequest, pm.MemoryLimit))
		}
		break // only show first pod's meta in summary
	}

	if analysis != nil {
		b.WriteString(fmt.Sprintf("\nRoot cause: %s\n", analysis.RootCause))
		b.WriteString(fmt.Sprintf("\nEvidence: %s\n", analysis.Evidence))
		b.WriteString(fmt.Sprintf("\nAction: %s\n", analysis.Action))
	}

	grafanaURL := buildGrafanaURL(grafanaBaseURL, payload)
	if grafanaURL != "" {
		b.WriteString(fmt.Sprintf("\nGrafana: %s\n", grafanaURL))
	}

	return &Message{
		Text:       b.String(),
		Severity:   payload.Severity,
		ClusterID:  payload.ClusterId,
		AlertName:  payload.AlertName,
		Namespace:  payload.Namespace,
		PodName:    payload.PodName,
		GrafanaURL: grafanaURL,
		Payload:    payload,
		Analysis:   analysis,
	}
}

func buildGrafanaURL(baseURL string, payload *pb.AlertPayload) string {
	if baseURL == "" {
		return ""
	}

	params := url.Values{}
	params.Set("orgId", "1")
	params.Set("left", fmt.Sprintf(`["now-1h","now","Loki",{"expr":"{namespace=\"%s\", pod=\"%s\"}"}]`,
		payload.Namespace, payload.PodName))

	return fmt.Sprintf("%s/explore?%s", strings.TrimRight(baseURL, "/"), params.Encode())
}
