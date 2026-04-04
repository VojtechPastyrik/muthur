package evaluator

import (
	"fmt"
	"strings"
	"time"

	pb "github.com/VojtechPastyrik/muthur-central/proto"
)

func buildPrompt(payload *pb.AlertPayload) string {
	var b strings.Builder

	b.WriteString("You are a Kubernetes monitoring AI. Analyse the following alert and return ONLY a JSON object.\n\n")
	b.WriteString("Required JSON format:\n")
	b.WriteString(`{"severity":"critical|warning|info","root_cause":"one sentence based on logs and metrics","evidence":"specific log lines or metric trends supporting this","action":"recommended immediate action","silence":false,"silence_reason":"only if silence=true"}`)
	b.WriteString("\n\n")
	b.WriteString("Rules:\n")
	b.WriteString("- Base conclusions only on provided data\n")
	b.WriteString("- Identify metric trends (rising, stable, sudden spike) and relate to alert timeline\n")
	b.WriteString("- Logs are already redacted — never attempt to reconstruct original values\n")
	b.WriteString("- Return only JSON, nothing before or after\n\n")

	b.WriteString(fmt.Sprintf("Cluster: %s\n", payload.ClusterId))
	b.WriteString(fmt.Sprintf("Alert: %s\n", payload.AlertName))
	b.WriteString(fmt.Sprintf("Severity: %s\n", payload.Severity))
	b.WriteString(fmt.Sprintf("Namespace: %s\n", payload.Namespace))
	b.WriteString(fmt.Sprintf("Fired at: %s\n", time.Unix(payload.FiredAt, 0).UTC().Format(time.RFC3339)))

	if payload.Summary != "" {
		b.WriteString(fmt.Sprintf("Summary: %s\n", payload.Summary))
	}
	if payload.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", payload.Description))
	}

	if payload.Target != nil {
		t := payload.Target
		b.WriteString(fmt.Sprintf("\nTarget type: %s\n", t.TargetType))
		if t.PodName != "" {
			b.WriteString(fmt.Sprintf("Pod: %s\n", t.PodName))
		}
		if t.Deployment != "" {
			b.WriteString(fmt.Sprintf("Deployment: %s\n", t.Deployment))
		}
		if t.Daemonset != "" {
			b.WriteString(fmt.Sprintf("DaemonSet: %s\n", t.Daemonset))
		}
		if t.Node != "" {
			b.WriteString(fmt.Sprintf("Node: %s\n", t.Node))
		}
		if t.Pvc != "" {
			b.WriteString(fmt.Sprintf("PVC: %s\n", t.Pvc))
		}
		if len(t.ResolvedPods) > 0 {
			b.WriteString(fmt.Sprintf("Resolved pods: %s\n", strings.Join(t.ResolvedPods, ", ")))
		}
	}

	if len(payload.RedactedLogs) > 0 {
		b.WriteString("\n--- Redacted Logs ---\n")
		for _, line := range payload.RedactedLogs {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}

	b.WriteString(fmt.Sprintf("\nRedaction stats: %d total lines, %d redacted lines, %d total replacements\n",
		payload.TotalLogLines, payload.RedactedLogLines, payload.TotalReplacements))

	if len(payload.Metrics) > 0 {
		b.WriteString("\n--- Metrics ---\n")
		for _, series := range payload.Metrics {
			b.WriteString(fmt.Sprintf("\nMetric: %s", series.MetricName))
			if series.Description != "" {
				b.WriteString(fmt.Sprintf(" (%s)", series.Description))
			}
			if series.Unit != "" {
				b.WriteString(fmt.Sprintf(" [%s]", series.Unit))
			}
			b.WriteString("\n")

			if len(series.Points) > 0 {
				b.WriteString("Timestamp                | Value\n")
				b.WriteString("-------------------------|------------------\n")
				for _, p := range series.Points {
					ts := time.Unix(p.Timestamp, 0).UTC().Format(time.RFC3339)
					b.WriteString(fmt.Sprintf("%-25s| %.4f\n", ts, p.Value))
				}
			}
		}
	}

	if len(payload.PodMetas) > 0 {
		b.WriteString("\n--- Pod Metadata ---\n")
		for _, pm := range payload.PodMetas {
			b.WriteString(fmt.Sprintf("Pod: %s, Node: %s, Phase: %s, Restarts: %d\n",
				pm.PodName, pm.NodeName, pm.Phase, pm.RestartCount))
			b.WriteString(fmt.Sprintf("  Memory: request=%s limit=%s, CPU: request=%s limit=%s\n",
				pm.MemoryRequest, pm.MemoryLimit, pm.CpuRequest, pm.CpuLimit))
		}
	}

	if len(payload.Labels) > 0 {
		b.WriteString("\n--- Labels ---\n")
		for _, l := range payload.Labels {
			b.WriteString(fmt.Sprintf("%s=%s\n", l.Name, l.Value))
		}
	}

	return b.String()
}
