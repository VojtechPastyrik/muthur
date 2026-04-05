package notify

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// FormatMessage wraps the payload, analysis, and grafana URL into a Message.
// Per-channel rendering is each notifier's responsibility — Discord uses
// embeds, Telegram uses HTML, Slack uses Block Kit attachments, etc.
func FormatMessage(payload *pb.AlertPayload, analysis *evaluator.Analysis, grafanaBaseURL string) *Message {
	return &Message{
		Payload:    payload,
		Analysis:   analysis,
		GrafanaURL: buildGrafanaURL(grafanaBaseURL, payload),
	}
}

func buildGrafanaURL(baseURL string, payload *pb.AlertPayload) string {
	if baseURL == "" || payload == nil {
		return ""
	}

	params := url.Values{}
	params.Set("orgId", "1")
	params.Set("left", fmt.Sprintf(`["now-1h","now","Loki",{"expr":"{namespace=\"%s\", pod=\"%s\"}"}]`,
		payload.Namespace, payload.PodName))

	return fmt.Sprintf("%s/explore?%s", strings.TrimRight(baseURL, "/"), params.Encode())
}

// targetLine returns a short "pod / name" or "deployment / name" string,
// empty when nothing useful is set.
func targetLine(payload *pb.AlertPayload) string {
	if payload == nil || payload.Target == nil {
		return ""
	}
	t := payload.Target
	line := t.TargetType
	switch {
	case t.PodName != "":
		line += " / " + t.PodName
	case t.Deployment != "":
		line += " / " + t.Deployment
	case t.Daemonset != "":
		line += " / " + t.Daemonset
	case t.Node != "":
		line += " / " + t.Node
	case t.Pvc != "":
		line += " / " + t.Pvc
	}
	return line
}

// restartInfo returns a short string like "3 restarts" when a pod has been
// restarting, otherwise empty.
func restartInfo(payload *pb.AlertPayload) string {
	if payload == nil {
		return ""
	}
	for _, pm := range payload.PodMetas {
		if pm.RestartCount > 0 {
			return fmt.Sprintf("%d restarts", pm.RestartCount)
		}
	}
	return ""
}
