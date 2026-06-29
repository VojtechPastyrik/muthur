package evaluator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur/proto"
)

// Evaluator must satisfy the Analyzer contract the pipeline depends on.
var _ Analyzer = (*Evaluator)(nil)

const validAnalysisJSON = `{"severity":"critical","root_cause":"OOMKilled","evidence":"container exceeded memory limit","action":"raise memory limit","confidence":"high","grounding":"stated","silence":false}`

const invalidAnalysisJSON = `{"severity":"nope","root_cause":"","evidence":"","action":"","confidence":"sky-high","grounding":"vibes","silence":false}`

// fakeProvider returns a scripted sequence of outputs/errors so the shared
// validate-retry-degrade loop can be exercised without a network.
type fakeProvider struct {
	outputs []json.RawMessage
	errs    []error
	calls   int
}

func (f *fakeProvider) name() string     { return "fake" }
func (f *fakeProvider) model() string    { return "fake-1" }
func (f *fakeProvider) structured() bool { return true }

func (f *fakeProvider) complete(_ context.Context, _ Prompt) (json.RawMessage, usage, error) {
	i := f.calls
	f.calls++
	if i < len(f.errs) && f.errs[i] != nil {
		return nil, usage{}, f.errs[i]
	}
	var out json.RawMessage
	if i < len(f.outputs) {
		out = f.outputs[i]
	}
	return out, usage{input: 10, output: 5}, nil
}

func newTestEvaluator(p provider, maxRetries int) *Evaluator {
	return &Evaluator{provider: p, maxRetries: maxRetries, logger: zap.NewNop()}
}

func TestEvaluator_ValidFirstTry(t *testing.T) {
	f := &fakeProvider{outputs: []json.RawMessage{json.RawMessage(validAnalysisJSON)}}
	e := newTestEvaluator(f, 1)

	a, err := e.run(context.Background(), Prompt{User: "prompt"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if f.calls != 1 {
		t.Errorf("calls = %d, want 1", f.calls)
	}
	if a.Severity != "critical" || a.RootCause != "OOMKilled" {
		t.Errorf("unexpected analysis: %+v", a)
	}
}

func TestEvaluator_InvalidThenValid(t *testing.T) {
	f := &fakeProvider{outputs: []json.RawMessage{
		json.RawMessage(invalidAnalysisJSON),
		json.RawMessage(validAnalysisJSON),
	}}
	e := newTestEvaluator(f, 1)

	a, err := e.run(context.Background(), Prompt{User: "prompt"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if f.calls != 2 {
		t.Errorf("calls = %d, want 2 (one corrective retry)", f.calls)
	}
	if a.Severity != "critical" {
		t.Errorf("unexpected analysis: %+v", a)
	}
}

func TestEvaluator_InvalidTwice_Degrades(t *testing.T) {
	f := &fakeProvider{outputs: []json.RawMessage{
		json.RawMessage(invalidAnalysisJSON),
		json.RawMessage(invalidAnalysisJSON),
	}}
	e := newTestEvaluator(f, 1)

	a, err := e.run(context.Background(), Prompt{User: "prompt"})
	if a != nil {
		t.Errorf("analysis = %+v, want nil on degrade", a)
	}
	if !errors.Is(err, ErrDegraded) {
		t.Fatalf("err = %v, want ErrDegraded", err)
	}
	if f.calls != 2 {
		t.Errorf("calls = %d, want 2 (initial + one retry)", f.calls)
	}
}

func TestEvaluator_TransportError_NoRetryLoop(t *testing.T) {
	f := &fakeProvider{errs: []error{errors.New("dial tcp: connection refused")}}
	e := newTestEvaluator(f, 1)

	a, err := e.run(context.Background(), Prompt{User: "prompt"})
	if a != nil {
		t.Errorf("analysis = %+v, want nil", a)
	}
	if err == nil {
		t.Fatal("want error on transport failure")
	}
	if errors.Is(err, ErrDegraded) {
		t.Error("transport error should not be reported as ErrDegraded")
	}
	if f.calls != 1 {
		t.Errorf("calls = %d, want 1 (transport error is not corrective-retried)", f.calls)
	}
}

func TestEvaluator_ZeroRetries_DegradesImmediately(t *testing.T) {
	f := &fakeProvider{outputs: []json.RawMessage{json.RawMessage(invalidAnalysisJSON)}}
	e := newTestEvaluator(f, 0)

	_, err := e.run(context.Background(), Prompt{User: "prompt"})
	if !errors.Is(err, ErrDegraded) {
		t.Fatalf("err = %v, want ErrDegraded", err)
	}
	if f.calls != 1 {
		t.Errorf("calls = %d, want 1", f.calls)
	}
}

// Evaluate/EvaluateIncident wire the prompt builders into the same loop.
func TestEvaluator_EvaluateContract(t *testing.T) {
	f := &fakeProvider{outputs: []json.RawMessage{json.RawMessage(validAnalysisJSON)}}
	e := newTestEvaluator(f, 1)

	payload := &pb.AlertPayload{AlertName: "KubePodCrashLooping", ClusterId: "cluster-test"}
	a, err := e.Evaluate(context.Background(), payload, nil)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if a.Action != "raise memory limit" {
		t.Errorf("unexpected analysis: %+v", a)
	}
	if e.Name() != "fake" {
		t.Errorf("Name() = %q, want fake", e.Name())
	}
}

// The default/empty provider must select Anthropic and refuse without a key,
// proving the no-new-config path stays Anthropic.
func TestNew_DefaultsToAnthropic(t *testing.T) {
	e, err := New(Config{APIKey: "sk-test"}, zap.NewNop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.Name() != "anthropic" {
		t.Errorf("Name() = %q, want anthropic", e.Name())
	}
	if _, err := New(Config{}, zap.NewNop()); err == nil {
		t.Error("want error when anthropic provider has no API key")
	}
}

func TestNew_UnknownProvider(t *testing.T) {
	if _, err := New(Config{Provider: "gemini"}, zap.NewNop()); err == nil {
		t.Error("want error for unknown provider")
	}
}
