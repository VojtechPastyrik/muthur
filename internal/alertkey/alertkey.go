// Package alertkey derives the stable identifier shared across muthur subsystems
// for a single alert/incident. The same value keys the persisted incident
// record (internal/history) and the operator-feedback entry (internal/feedback),
// so a feedback verdict and its incident cross-reference by ID.
package alertkey

import (
	"crypto/sha256"
	"fmt"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

// ID returns the stable per-alert identifier: the first 16 hex chars (64 bits)
// of SHA256 over the alert's identity-bearing fields. Deterministic for a given
// firing, so the same alert always maps to the same incident/feedback record.
func ID(p *pb.AlertPayload) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%d",
		p.ClusterId, p.AlertName, p.Namespace, p.PodName, p.FiredAt)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h)[:16]
}
