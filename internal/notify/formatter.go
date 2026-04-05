package notify

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/VojtechPastyrik/muthur/internal/evaluator"
	pb "github.com/VojtechPastyrik/muthur/proto"
)

// FormatMessage wraps the payload and analysis into a Message. The Grafana
// deep link is built from payload.GrafanaBaseUrl — this is provided by the
// collector so each cluster points to its own Grafana instance. When the
// collector omits it, notifications contain no Grafana link.
func FormatMessage(payload *pb.AlertPayload, analysis *evaluator.Analysis) *Message {
	return &Message{
		Payload:    payload,
		Analysis:   analysis,
		GrafanaURL: buildGrafanaURL(payload),
	}
}

func buildGrafanaURL(payload *pb.AlertPayload) string {
	if payload == nil || payload.GrafanaBaseUrl == "" {
		return ""
	}

	params := url.Values{}
	params.Set("orgId", "1")
	params.Set("left", fmt.Sprintf(`["now-1h","now","Loki",{"expr":"{namespace=\"%s\", pod=\"%s\"}"}]`,
		payload.Namespace, payload.PodName))

	return fmt.Sprintf("%s/explore?%s", strings.TrimRight(payload.GrafanaBaseUrl, "/"), params.Encode())
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
