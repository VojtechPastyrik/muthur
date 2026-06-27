package evaluator

import (
	"encoding/json"
	"fmt"
	"strings"
)

// This file is the single source of truth for the analysis contract. Both
// providers consume the same property definitions and the same validator, so
// the Anthropic tool schema and the OpenAI response_format schema can never
// drift apart, and every backend is held to the identical typed result.

// Canonical enums for the constrained analysis fields. Referenced by both the
// JSON Schema (advertised to the model) and validateAnalysis (enforced on the
// way back), so the two are guaranteed to agree.
var (
	severityEnum   = []string{"critical", "warning", "info"}
	confidenceEnum = []string{"high", "medium", "low"}
	groundingEnum  = []string{"stated", "inferred"}
)

// analysisRequired lists the fields a valid analysis must always carry.
// silence_reason is intentionally excluded — it is only meaningful when
// silence is true.
func analysisRequired() []string {
	return []string{"severity", "root_cause", "evidence", "action", "confidence", "grounding", "silence"}
}

// analysisProperties is the canonical JSON Schema property map for the analysis
// struct. Anthropic uses it verbatim as the forced-tool input schema; the
// OpenAI-compatible provider folds it into a response_format JSON Schema.
func analysisProperties() map[string]any {
	return map[string]any{
		"severity": map[string]any{
			"type":        "string",
			"enum":        severityEnum,
			"description": "Overall severity of the situation based on the evidence.",
		},
		"root_cause": map[string]any{
			"type":        "string",
			"description": "One sentence root cause grounded in the provided logs and metrics.",
		},
		"evidence": map[string]any{
			"type":        "string",
			"description": "Specific log lines or metric trends supporting the root cause.",
		},
		"action": map[string]any{
			"type":        "string",
			"description": "Recommended immediate action.",
		},
		"confidence": map[string]any{
			"type":        "string",
			"enum":        confidenceEnum,
			"description": "Your certainty in the root cause. 'high' only when the logs/metrics state it directly; 'low' when you are guessing from sparse data.",
		},
		"grounding": map[string]any{
			"type":        "string",
			"enum":        groundingEnum,
			"description": "'stated' if the root cause is read directly from the provided data; 'inferred' if you are reasoning beyond what the data literally says.",
		},
		"silence": map[string]any{
			"type":        "boolean",
			"description": "True only if this alert is noise that should be silenced.",
		},
		"silence_reason": map[string]any{
			"type":        "string",
			"description": "Why the alert should be silenced. Only set when silence is true.",
		},
	}
}

// analysisJSONSchema builds the full JSON Schema object for the OpenAI
// response_format. OpenAI strict structured outputs require that every property
// appears in `required` and that additionalProperties is false, so the optional
// silence_reason is expressed as a nullable string rather than omitted. Models
// that ignore strictness still produce schema-shaped output we then validate.
func analysisJSONSchema() map[string]any {
	props := analysisProperties()
	props["silence_reason"] = map[string]any{
		"type":        []string{"string", "null"},
		"description": "Why the alert should be silenced. Only set when silence is true; null otherwise.",
	}
	return map[string]any{
		"type":                 "object",
		"properties":           props,
		"required":             []string{"severity", "root_cause", "evidence", "action", "confidence", "grounding", "silence", "silence_reason"},
		"additionalProperties": false,
	}
}

// decodeAndValidate unmarshals raw model output into an Analysis and enforces
// the canonical contract. It is deliberately strict: any missing required field
// or out-of-enum value is an error, which drives the corrective-retry /
// degrade path. There is no markdown stripping or lenient parsing — malformed
// output is rejected, never massaged.
func decodeAndValidate(raw json.RawMessage) (*Analysis, error) {
	var a Analysis
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("decode analysis: %w", err)
	}
	if err := validateAnalysis(&a); err != nil {
		return nil, err
	}
	return &a, nil
}

// validateAnalysis enforces the canonical schema on a decoded Analysis. This is
// the guarantee that holds regardless of which provider produced the output and
// whether that provider could enforce the schema natively.
func validateAnalysis(a *Analysis) error {
	if !inEnum(severityEnum, a.Severity) {
		return fmt.Errorf("severity %q not one of %v", a.Severity, severityEnum)
	}
	if strings.TrimSpace(a.RootCause) == "" {
		return fmt.Errorf("root_cause is required")
	}
	if strings.TrimSpace(a.Evidence) == "" {
		return fmt.Errorf("evidence is required")
	}
	if strings.TrimSpace(a.Action) == "" {
		return fmt.Errorf("action is required")
	}
	if !inEnum(confidenceEnum, a.Confidence) {
		return fmt.Errorf("confidence %q not one of %v", a.Confidence, confidenceEnum)
	}
	if !inEnum(groundingEnum, a.Grounding) {
		return fmt.Errorf("grounding %q not one of %v", a.Grounding, groundingEnum)
	}
	return nil
}

func inEnum(allowed []string, v string) bool {
	for _, a := range allowed {
		if a == v {
			return true
		}
	}
	return false
}
