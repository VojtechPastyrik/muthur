package evaluator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// decodeRequest reads the chat request body for assertions.
func decodeRequest(t *testing.T, r *http.Request) (chatRequest, map[string]any) {
	t.Helper()
	body, _ := io.ReadAll(r.Body)
	var req chatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	// Re-decode response_format loosely to inspect its type.
	var loose struct {
		ResponseFormat map[string]any `json:"response_format"`
	}
	_ = json.Unmarshal(body, &loose)
	return req, loose.ResponseFormat
}

func okChatResponse(content string) string {
	resp := chatResponse{}
	resp.Choices = append(resp.Choices, struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}{})
	resp.Choices[0].Message.Content = content
	resp.Usage.PromptTokens = 100
	resp.Usage.CompletionTokens = 20
	b, _ := json.Marshal(resp)
	return string(b)
}

func TestOpenAI_SchemaMode(t *testing.T) {
	var gotFormat string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-1" {
			t.Errorf("missing/wrong auth header: %q", r.Header.Get("Authorization"))
		}
		_, rf := decodeRequest(t, r)
		gotFormat, _ = rf["type"].(string)
		io.WriteString(w, okChatResponse(validAnalysisJSON))
	}))
	defer srv.Close()

	p := newOpenAIProvider(srv.URL, "sk-1", "qwen2.5", modeSchema, 0, 5*time.Second, zap.NewNop())
	raw, u, err := p.complete(context.Background(), "analyse this")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if gotFormat != "json_schema" {
		t.Errorf("response_format.type = %q, want json_schema", gotFormat)
	}
	if u.input != 100 || u.output != 20 {
		t.Errorf("usage = %+v", u)
	}
	if _, err := decodeAndValidate(raw); err != nil {
		t.Errorf("validate: %v", err)
	}
	if !p.structured() {
		t.Error("schema mode should report structured()")
	}
}

func TestOpenAI_JSONObjectMode(t *testing.T) {
	var gotFormat, gotPrompt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, rf := decodeRequest(t, r)
		gotFormat, _ = rf["type"].(string)
		gotPrompt = req.Messages[0].Content
		io.WriteString(w, okChatResponse(validAnalysisJSON))
	}))
	defer srv.Close()

	p := newOpenAIProvider(srv.URL, "", "llama3.1", modeJSONObject, 0, 5*time.Second, zap.NewNop())
	raw, _, err := p.complete(context.Background(), "analyse this")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if gotFormat != "json_object" {
		t.Errorf("response_format.type = %q, want json_object", gotFormat)
	}
	if !strings.Contains(gotPrompt, "single JSON object") {
		t.Error("json-object mode must append the shape instruction to the prompt")
	}
	if _, err := decodeAndValidate(raw); err != nil {
		t.Errorf("validate: %v", err)
	}
	if p.structured() {
		t.Error("json-object mode is best-effort, structured() should be false")
	}
}

func TestOpenAI_AutoDowngrade(t *testing.T) {
	var calls int
	var formats []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, rf := decodeRequest(t, r)
		f, _ := rf["type"].(string)
		formats = append(formats, f)
		if f == "json_schema" {
			// Emulate an endpoint that does not support JSON Schema.
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":{"message":"response_format json_schema is not supported by this model"}}`)
			return
		}
		io.WriteString(w, okChatResponse(validAnalysisJSON))
	}))
	defer srv.Close()

	p := newOpenAIProvider(srv.URL, "", "ollama-model", modeAuto, 0, 5*time.Second, zap.NewNop())
	raw, _, err := p.complete(context.Background(), "analyse this")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2 (schema probe then json-object)", calls)
	}
	if len(formats) != 2 || formats[0] != "json_schema" || formats[1] != "json_object" {
		t.Errorf("formats = %v, want [json_schema json_object]", formats)
	}
	if p.structured() {
		t.Error("after auto-downgrade, structured() should be false")
	}
	if _, err := decodeAndValidate(raw); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestOpenAI_HardErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "boom")
	}))
	defer srv.Close()

	// json-object mode so a 500 is not mistaken for a schema-capability gap.
	p := newOpenAIProvider(srv.URL, "", "m", modeJSONObject, 0, time.Second, zap.NewNop())
	if _, _, err := p.complete(context.Background(), "x"); err == nil {
		t.Error("want error on repeated 5xx")
	}
}

func TestParseSchemaMode(t *testing.T) {
	cases := map[string]schemaMode{
		"":            modeAuto,
		"auto":        modeAuto,
		"schema":      modeSchema,
		"json-object": modeJSONObject,
		"json_object": modeJSONObject,
	}
	for in, want := range cases {
		got, err := parseSchemaMode(in)
		if err != nil || got != want {
			t.Errorf("parseSchemaMode(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := parseSchemaMode("garbage"); err == nil {
		t.Error("want error for invalid mode")
	}
}
