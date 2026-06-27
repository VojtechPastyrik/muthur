package evaluator

// Analysis is the structured verdict an Analyzer returns for an alert or
// incident. It is provider-agnostic: every backend maps the canonical schema
// (see schema.go) onto this exact type, so the rest of the system never sees
// raw model text.
type Analysis struct {
	Severity  string `json:"severity"`
	RootCause string `json:"root_cause"`
	Evidence  string `json:"evidence"`
	Action    string `json:"action"`
	// Confidence is the model's self-assessed certainty in the root cause:
	// "high", "medium", or "low". Surfaced in notifications so on-call can
	// calibrate trust instead of treating every verdict as equally sure.
	Confidence string `json:"confidence"`
	// Grounding is "stated" when the root cause is read directly from the
	// provided logs/metrics, or "inferred" when the model is reasoning beyond
	// what the data literally says. Separates observation from speculation.
	Grounding     string `json:"grounding"`
	Silence       bool   `json:"silence"`
	SilenceReason string `json:"silence_reason,omitempty"`
}

// Example is a past analysis with an operator verdict, fed back to the model as
// a few-shot signal so evaluations improve per-cluster over time. Defined here
// (rather than in the feedback package) so evaluator has no dependency on
// feedback — the dependency runs the other way.
type Example struct {
	AlertName string
	Verdict   string // "useful" or "wrong"
	Analysis  *Analysis
}
