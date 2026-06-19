package evaluator

import (
	"encoding/json"
	"testing"
)

// TestAnalysisTool_Schema verifies the forced-tool schema advertises the fields
// the pipeline depends on, with the right required set.
func TestAnalysisTool_Schema(t *testing.T) {
	tool := analysisTool()
	if tool.Name != "report_analysis" {
		t.Fatalf("tool name = %q, want report_analysis", tool.Name)
	}
	props, ok := tool.InputSchema.Properties.(map[string]any)
	if !ok {
		t.Fatal("properties is not a map")
	}
	for _, field := range []string{"severity", "root_cause", "evidence", "action", "silence", "silence_reason"} {
		if _, ok := props[field]; !ok {
			t.Errorf("schema missing property %q", field)
		}
	}
	wantRequired := map[string]bool{"severity": true, "root_cause": true, "evidence": true, "action": true, "silence": true}
	if len(tool.InputSchema.Required) != len(wantRequired) {
		t.Errorf("required = %v, want %d fields", tool.InputSchema.Required, len(wantRequired))
	}
	for _, r := range tool.InputSchema.Required {
		if !wantRequired[r] {
			t.Errorf("unexpected required field %q", r)
		}
	}
}

// TestAnalysis_Unmarshal confirms a tool-input payload decodes into Analysis.
func TestAnalysis_Unmarshal(t *testing.T) {
	raw := `{"severity":"critical","root_cause":"oom","evidence":"OOM killed","action":"raise limits","silence":false}`
	var a Analysis
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if a.Severity != "critical" || a.RootCause != "oom" || a.Silence {
		t.Errorf("unexpected analysis: %+v", a)
	}
}
