package evaluator

import (
	"fmt"
	"strings"
	"time"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

const promptIntro = `You are a Kubernetes monitoring AI. Analyse the alert data below and report your verdict by calling the report_analysis tool.

Rules:
- Base conclusions only on the provided data.
- Identify metric trends (rising, stable, sudden spike) and relate them to the alert timeline.
- Logs are already redacted — never attempt to reconstruct original values.
- Call report_analysis exactly once.
`

const incidentIntro = `You are a Kubernetes monitoring AI. The following alerts fired close together in the same cluster and are likely facets of ONE incident. Analyse them together and report a single unified verdict by calling the report_analysis tool.

Rules:
- Identify the single underlying root cause that best explains the whole group, not each alert in isolation.
- If one alert is the trigger and the others are cascading effects, say so in root_cause and evidence.
- Base conclusions only on the provided data. Logs are already redacted.
- Set severity to the highest warranted by the group.
- Call report_analysis exactly once.
`

// buildPrompt renders the single-alert prompt.
func buildPrompt(payload *pb.AlertPayload, examples []Example) string {
	var b strings.Builder
	b.WriteString(promptIntro)
	writeExamples(&b, examples)
	b.WriteString("\n=== Alert ===\n")
	renderAlert(&b, payload)
	return b.String()
}

// buildIncidentPrompt renders the multi-alert (correlated incident) prompt.
func buildIncidentPrompt(payloads []*pb.AlertPayload, examples []Example) string {
	var b strings.Builder
	b.WriteString(incidentIntro)
	writeExamples(&b, examples)
	b.WriteString(fmt.Sprintf("\n=== Incident: %d correlated alerts ===\n", len(payloads)))
	for i, p := range payloads {
		b.WriteString(fmt.Sprintf("\n--- Alert %d of %d ---\n", i+1, len(payloads)))
		renderAlert(&b, p)
	}
	return b.String()
}

// writeExamples injects past analyses with operator verdicts as a few-shot
// signal. "wrong" examples steer the model away from a prior mistake; "useful"
// examples reinforce a good pattern. This is how the feedback loop closes.
func writeExamples(b *strings.Builder, examples []Example) {
	if len(examples) == 0 {
		return
	}
	b.WriteString("\n=== Operator feedback on past analyses (learn from these) ===\n")
	for _, ex := range examples {
		if ex.Analysis == nil {
			continue
		}
		switch ex.Verdict {
		case "wrong":
			b.WriteString(fmt.Sprintf("- For alert %q, operators marked this root cause as WRONG: %q. Avoid this mistake.\n",
				ex.AlertName, ex.Analysis.RootCause))
		case "useful":
			b.WriteString(fmt.Sprintf("- For alert %q, operators confirmed this root cause as correct: %q.\n",
				ex.AlertName, ex.Analysis.RootCause))
		}
	}
}

// renderAlert writes one alert's data block. Shared by the single-alert and
// incident prompts.
func renderAlert(b *strings.Builder, payload *pb.AlertPayload) {
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
		b.WriteString(fmt.Sprintf("Target type: %s\n", t.TargetType))
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
}

// Signature returns a stable, human-readable text signature of an alert used by
// the semantic cache to find near-duplicate analyses. It deliberately excludes
// pod name and timestamps so that the same failure on a different pod produces a
// similar vector.
func Signature(payload *pb.AlertPayload) string {
	var b strings.Builder
	b.WriteString(payload.AlertName)
	b.WriteString(" ")
	b.WriteString(payload.Namespace)
	b.WriteString(" ")
	b.WriteString(payload.Severity)
	b.WriteString(" ")
	b.WriteString(payload.Summary)
	if payload.Target != nil {
		b.WriteString(" ")
		b.WriteString(payload.Target.TargetType)
		b.WriteString(" ")
		b.WriteString(payload.Target.Deployment)
	}
	for _, l := range payload.Labels {
		b.WriteString(" ")
		b.WriteString(l.Name)
		b.WriteString("=")
		b.WriteString(l.Value)
	}
	return b.String()
}
