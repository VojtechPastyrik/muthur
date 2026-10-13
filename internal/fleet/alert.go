package fleet

import (
	"fmt"
	"time"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

// Synthetic alert names emitted for fleet transitions. Fixed so operators can
// route or silence them like any other alert name.
const (
	// AlertName covers collector liveness: the beats stopped.
	AlertName = "MuthurCollectorDown"
	// PipelineAlertName covers the cluster's own alerting path: the collector
	// is alive, but no Watchdog alert is arriving through it any more.
	PipelineAlertName = "MuthurAlertingPipelineDown"
)

// SyntheticAlert renders a watchdog Event as an AlertPayload. Reusing the alert
// shape means collector outages flow through the existing router, notifiers,
// and formatting rather than growing a parallel delivery path — a channel that
// only ever carries one message type is a channel nobody tests.
//
// The payload carries no logs, metrics, or events: there is nothing to enrich
// with, because the thing that would have collected them is the thing that is
// gone. Analysis is deliberately nil at the call site — an LLM cannot add
// anything to "this collector stopped responding".
func SyntheticAlert(ev Event, now time.Time) *pb.AlertPayload {
	st := ev.State
	name := AlertName
	if ev.Status == StatusPipelineDown || ev.Status == StatusPipelineRecovered {
		name = PipelineAlertName
	}

	p := &pb.AlertPayload{
		ClusterId: st.ClusterID,
		AlertName: name,
		Severity:  "critical",
		FiredAt:   now.Unix(),
		Status:    "firing",
		Labels: []*pb.Label{
			{Name: "alertname", Value: name},
			{Name: "severity", Value: "critical"},
			{Name: "cluster", Value: st.ClusterID},
			{Name: "source", Value: "muthur-watchdog"},
		},
	}
	if st.Version != "" {
		p.Labels = append(p.Labels, &pb.Label{Name: "collector_version", Value: st.Version})
	}

	switch ev.Status {
	case StatusDown:
		p.Summary = fmt.Sprintf("Collector for cluster %q stopped sending heartbeats", st.ClusterID)
		p.Description = downDescription(ev, now)

	case StatusRecovered:
		p.Status = "resolved"
		p.Severity = "info"
		p.Summary = fmt.Sprintf("Collector for cluster %q is heartbeating again", st.ClusterID)
		p.Description = recoveredDescription(st)

	case StatusPipelineDown:
		p.Summary = fmt.Sprintf("Alerts from cluster %q are not being delivered", st.ClusterID)
		p.Description = fmt.Sprintf(
			"The collector is alive and reporting, but no Watchdog alert has arrived for %s. "+
				"Watchdog fires continuously by design, so its absence means the path from "+
				"Prometheus through AlertManager to the collector is broken — a crashed "+
				"Prometheus, a stopped AlertManager, or a routing change. Alerts raised in "+
				"this cluster are being lost, not delayed.",
			ev.Age.Truncate(time.Second))

	case StatusPipelineRecovered:
		p.Status = "resolved"
		p.Severity = "info"
		p.Summary = fmt.Sprintf("Alert delivery restored for cluster %q", st.ClusterID)
		p.Description = "Watchdog alerts are arriving through the cluster's AlertManager again."

	case StatusRetired:
		// Closes a previously-paged outage for a cluster that has since been
		// decommissioned, so the open alert does not dangle in the channel.
		p.Status = "resolved"
		p.Severity = "info"
		p.Summary = fmt.Sprintf("Cluster %q retired from the fleet", st.ClusterID)
		p.Description = "The collector was down and the cluster has been decommissioned " +
			"(tenant revoked or removed, or the collector announced shutdown). " +
			"No further alerts will be raised for it."
	}
	return p
}

func downDescription(ev Event, now time.Time) string {
	st := ev.State
	desc := fmt.Sprintf("No heartbeat for %s (last seen %s).",
		ev.Age.Truncate(time.Second),
		time.Unix(st.LastSeen, 0).UTC().Format(time.RFC3339),
	)
	if st.Version != "" {
		desc += fmt.Sprintf(" Collector version %s.", st.Version)
	}
	if st.StartedAt > 0 {
		desc += fmt.Sprintf(" Collector had been up %s.",
			time.Unix(st.LastSeen, 0).Sub(time.Unix(st.StartedAt, 0)).Truncate(time.Minute))
	}
	desc += " Alerts from this cluster are not reaching muthur: either the collector, " +
		"the cluster, or the network between them is down. Alerts raised there are " +
		"being lost, not delivered."
	return desc
}

func recoveredDescription(st State) string {
	// A changed StartedAt is the difference between "the network healed" and
	// "the pod was replaced"; both end the outage, but only one of them points
	// at a crash worth investigating.
	desc := "Heartbeats resumed."
	if st.StartedAt > 0 {
		desc += fmt.Sprintf(" Collector process started at %s.",
			time.Unix(st.StartedAt, 0).UTC().Format(time.RFC3339))
	}
	if st.AlertsForwarded > 0 {
		desc += fmt.Sprintf(" %d alerts forwarded since start.", st.AlertsForwarded)
	}
	return desc
}
