package openai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/llm/conformance"
)

// The reference adapter passes the same table mock has passed since M2.1
// (docs/SPEC.md §11, acceptance criterion 8).
func TestConformance(t *testing.T) { conformance.Run(t, Name, harness) }

func provider(t *testing.T, f *fakeServer, url string, cfg llm.Config) *Provider {
	t.Helper()
	if cfg.Model == "" {
		cfg.Model = "gpt-4o-mini"
	}
	cfg.BaseURL = url
	if cfg.Env == nil {
		cfg.Env = env(map[string]string{keyVar: "sk-test"})
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = f
	return p
}

// Construction is configuration only: OpenAI's endpoint defaults the
// model, a different endpoint requires --model, window known, no
// credential in the URL, key presence checked for OpenAI's endpoint only.
func TestNewValidatesConfiguration(t *testing.T) {
	noKey := env(map[string]string{})
	if _, err := New(llm.Config{Env: noKey}); err == nil || !strings.Contains(err.Error(), keyVar) {
		t.Errorf("default model, no key: %v", err)
	}
	if _, err := New(llm.Config{BaseURL: "http://localhost:8000/v1", Env: noKey}); err == nil || !strings.Contains(err.Error(), "--model") {
		t.Errorf("custom endpoint, no model: %v", err)
	}
	if _, err := New(llm.Config{Model: "gpt-4o", Env: noKey}); err == nil || !strings.Contains(err.Error(), keyVar) {
		t.Errorf("no key on the default endpoint: %v", err)
	}
	if _, err := New(llm.Config{Model: "mystery-7b", BaseURL: "http://localhost:8000/v1", Env: noKey}); err == nil || !strings.Contains(err.Error(), "max_context") {
		t.Errorf("unknown window: %v", err)
	}
	p, err := New(llm.Config{Model: "mystery-7b", BaseURL: "http://localhost:8000/v1", MaxContext: 8192, Env: noKey})
	if err != nil || p.Limits().MaxContext != 8192 || p.Native().Reasoning || p.priced {
		t.Errorf("local endpoint: %v %+v", err, p)
	}
	p, err = New(llm.Config{Model: "gpt-5-mini", Env: env(map[string]string{keyVar: "k"})})
	if err != nil || p.Limits().MaxContext != 400000 || !p.Native().Reasoning || !p.priced || p.Native().PromptCaching {
		t.Errorf("known model: %v %+v", err, p)
	}
	p, err = New(llm.Config{Env: env(map[string]string{keyVar: "k"})})
	if err != nil || p.model != DefaultModel || p.Limits().MaxContext != 1050000 || p.Native().Reasoning || !p.effortNone || !p.priced {
		t.Errorf("default luna: %v %+v", err, p)
	}
	if _, err := New(llm.Config{Model: "gpt-4o", BaseURL: "https://u:p@api.example.com/v1", Env: noKey}); err == nil {
		t.Error("credentials in the base URL accepted")
	}
	if _, err := New(llm.Config{Model: "gpt-4o", BaseURL: "not a url", Env: noKey}); err == nil {
		t.Error("relative base URL accepted")
	}
}

// The neutral request maps onto the wire: one system message, tool results
// as tool messages, tools as functions, the reservation as
// max_completion_tokens, effort as reasoning_effort, the bearer header.
func TestRequestEncoding(t *testing.T) {
	f, srv := newFake(t, []conformance.Turn{{Text: "ok"}})
	defer srv.Close()
	p := provider(t, f, srv.URL, llm.Config{Model: "gpt-5"})
	r := llm.Request{
		System: []llm.Block{{Text: "A", Cacheable: true}, {Text: "B"}},
		Tools:  []llm.Tool{{Name: "run_check", Description: "d", Schema: json.RawMessage(`{"type":"object"}`)}},
		Messages: []llm.Message{
			{Role: llm.RoleUser, Text: "begin"},
			{Role: llm.RoleAssistant, Text: "thinking", ToolCalls: []llm.ToolCall{{ID: "c1", Name: "run_check", Input: json.RawMessage(`{"id":"x"}`)}}},
			{Role: llm.RoleUser, ToolResults: []llm.ToolResult{{CallID: "c1", Content: "out", IsError: true}}},
		},
		MaxTokens: 512, Effort: llm.EffortMax,
	}
	if _, err := llm.Complete(context.Background(), p, r); err != nil {
		t.Fatal(err)
	}
	body := f.lastBody()
	if f.auth != "Bearer sk-test" {
		t.Errorf("auth header %q", f.auth)
	}
	msgs := body["messages"].([]any)
	if len(msgs) != 4 {
		t.Fatalf("%d messages: %v", len(msgs), msgs)
	}
	sys := msgs[0].(map[string]any)
	if sys["role"] != "system" || sys["content"] != "A\n\nB" {
		t.Errorf("system message: %v", sys)
	}
	asst := msgs[2].(map[string]any)
	if asst["role"] != "assistant" || asst["tool_calls"] == nil {
		t.Errorf("assistant message: %v", asst)
	}
	tool := msgs[3].(map[string]any)
	if tool["role"] != "tool" || tool["tool_call_id"] != "c1" || tool["content"] != "out" {
		t.Errorf("tool message: %v", tool)
	}
	if body["max_completion_tokens"] != float64(512) || body["reasoning_effort"] != "high" || body["tool_choice"] != "auto" || body["stream"] != true {
		t.Errorf("params: %v", body)
	}
	if _, has := body["max_tokens"]; has {
		t.Error("legacy max_tokens sent alongside max_completion_tokens")
	}
	tools := body["tools"].([]any)
	fn := tools[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "run_check" || fn["parameters"] == nil {
		t.Errorf("tools: %v", tools)
	}
}

// Capability differences are absorbed by the adapter, never by the loop:
// an endpoint that only knows max_tokens gets it; one that rejects
// reasoning_effort loses it and Native records that; one that rejects tools
// fails as unsupported (docs/SPEC.md §5.3).
func TestAdapterAbsorbsCapabilityDifferences(t *testing.T) {
	f, srv := newFake(t, []conformance.Turn{{Text: "ok"}, {Text: "ok"}})
	defer srv.Close()
	f.rejectMaxCompletion = true
	p := provider(t, f, srv.URL, llm.Config{Model: "gpt-5"})
	if _, err := llm.Complete(context.Background(), p, llm.Request{MaxTokens: 100, Messages: []llm.Message{{Role: llm.RoleUser, Text: "x"}}}); err != nil {
		t.Fatal(err)
	}
	if body := f.lastBody(); body["max_tokens"] != float64(100) || body["max_completion_tokens"] != nil {
		t.Errorf("legacy fallback not applied: %v", body)
	}
	// The second call goes straight to the legacy field.
	if _, err := llm.Complete(context.Background(), p, llm.Request{MaxTokens: 100, Messages: []llm.Message{{Role: llm.RoleUser, Text: "x"}}}); err != nil {
		t.Fatal(err)
	}
	if len(f.bodies) != 3 {
		t.Errorf("%d requests, want 3 (one retry, then direct)", len(f.bodies))
	}

	f, srv = newFake(t, []conformance.Turn{{Text: "ok"}})
	defer srv.Close()
	f.rejectReasoning = true
	p = provider(t, f, srv.URL, llm.Config{Model: "gpt-5"})
	if !p.Native().Reasoning {
		t.Fatal("gpt-5 should start with reasoning native")
	}
	if _, err := llm.Complete(context.Background(), p, llm.Request{Effort: llm.EffortHigh, Messages: []llm.Message{{Role: llm.RoleUser, Text: "x"}}}); err != nil {
		t.Fatal(err)
	}
	if p.Native().Reasoning {
		t.Error("Native.Reasoning still claims a feature the endpoint rejected")
	}
	if _, has := f.lastBody()["reasoning_effort"]; has {
		t.Error("reasoning_effort re-sent after rejection")
	}

	f, srv = newFake(t, []conformance.Turn{{Text: "ok"}})
	defer srv.Close()
	f.rejectToolsReasoning = true
	p = provider(t, f, srv.URL, llm.Config{Model: "gpt-5"})
	if _, err := llm.Complete(context.Background(), p, llm.Request{
		Effort:   llm.EffortHigh,
		Tools:    []llm.Tool{{Name: "t", Schema: json.RawMessage(`{}`)}},
		Messages: []llm.Message{{Role: llm.RoleUser, Text: "x"}},
	}); err != nil {
		t.Fatal(err)
	}
	if p.Native().Reasoning {
		t.Error("tools+reasoning retreat still claims Native.Reasoning")
	}
	if f.lastBody()["reasoning_effort"] != "none" {
		t.Errorf("tools+reasoning retry: %v", f.lastBody()["reasoning_effort"])
	}
	if len(f.bodies) != 2 {
		t.Errorf("want one retry, got %d requests", len(f.bodies))
	}

	f, srv = newFake(t, []conformance.Turn{{Text: "ok"}})
	defer srv.Close()
	f.rejectToolsReasoning = true
	p = provider(t, f, srv.URL, llm.Config{Model: DefaultModel})
	if p.Native().Reasoning {
		t.Fatal("luna should not claim reasoning on chat-completions tools")
	}
	if _, err := llm.Complete(context.Background(), p, llm.Request{
		Tools:    []llm.Tool{{Name: "t", Schema: json.RawMessage(`{}`)}},
		Messages: []llm.Message{{Role: llm.RoleUser, Text: "x"}},
	}); err != nil {
		t.Fatal(err)
	}
	if len(f.bodies) != 1 || f.lastBody()["reasoning_effort"] != "none" {
		t.Errorf("luna first shot: %d requests effort=%v", len(f.bodies), f.lastBody()["reasoning_effort"])
	}

	f, srv = newFake(t, []conformance.Turn{{Text: "ok"}})
	defer srv.Close()
	f.rejectTools = true
	p = provider(t, f, srv.URL, llm.Config{})
	_, err := llm.Complete(context.Background(), p, llm.Request{Tools: []llm.Tool{{Name: "t", Schema: json.RawMessage(`{}`)}}, Messages: []llm.Message{{Role: llm.RoleUser, Text: "x"}}})
	if llm.KindOf(err) != llm.ErrUnsupported {
		t.Errorf("tools rejected: %v", err)
	}
}

// Usage is normalized with cached tokens and priced from the table on
// OpenAI's endpoint; a custom endpoint reports tokens and null cost.
func TestUsageAndCost(t *testing.T) {
	turn := conformance.Turn{Text: "ok", Usage: llm.Usage{Input: 1000, Output: 100, CacheRead: 400}}
	f, srv := newFake(t, []conformance.Turn{turn})
	defer srv.Close()
	p := provider(t, f, srv.URL, llm.Config{Model: "gpt-4o-mini"})
	p.priced = true // as if the endpoint were api.openai.com
	resp, err := llm.Complete(context.Background(), p, llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Text: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Usage.Input != 1000 || resp.Usage.Output != 100 || resp.Usage.CacheRead != 400 {
		t.Errorf("usage %+v", resp.Usage)
	}
	// 600 uncached * 0.15 + 400 cached * 0.075 + 100 out * 0.60, per million.
	want := (600*0.15 + 400*0.075 + 100*0.60) / 1e6
	if resp.Usage.CostUSD == nil || *resp.Usage.CostUSD < want-1e-9 || *resp.Usage.CostUSD > want+1e-9 {
		t.Errorf("cost %v want %v", resp.Usage.CostUSD, want)
	}
	f, srv = newFake(t, []conformance.Turn{turn})
	defer srv.Close()
	p = provider(t, f, srv.URL, llm.Config{Model: "gpt-4o-mini"})
	resp, _ = llm.Complete(context.Background(), p, llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Text: "x"}}})
	if resp.Usage.CostUSD != nil {
		t.Errorf("a custom endpoint priced with OpenAI's table: %v", *resp.Usage.CostUSD)
	}
}

// Failures are classified so the loop ends the run honestly: overflow,
// auth, transport, a broken stream, malformed tool arguments.
func TestErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		kind   llm.ErrorKind
	}{
		{400, "This model's maximum context length is 8192 tokens", llm.ErrContextOverflow},
		{413, "payload too large", llm.ErrContextOverflow},
		{401, "bad key", llm.ErrAuth},
		{429, "rate limited", llm.ErrTransport},
		{500, "boom", llm.ErrTransport},
		{400, "tools are not supported for this model", llm.ErrUnsupported},
		{400, "something else entirely", llm.ErrResponse},
	} {
		f, srv := newFake(t, nil)
		f.status, f.errorBody = tc.status, tc.body
		p := provider(t, f, srv.URL, llm.Config{})
		_, err := llm.Complete(context.Background(), p, llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Text: "x"}}})
		if llm.KindOf(err) != tc.kind {
			t.Errorf("HTTP %d %q: %q (%v)", tc.status, tc.body, llm.KindOf(err), err)
		}
		srv.Close()
	}
	// A stream that ends without [DONE] but with a finish reason is a reply.
	f, srv := newFake(t, []conformance.Turn{{Text: "partial"}})
	defer srv.Close()
	f.noDone = true
	p := provider(t, f, srv.URL, llm.Config{})
	resp, err := llm.Complete(context.Background(), p, llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Text: "x"}}})
	if err != nil || resp.Text != "partial" {
		t.Errorf("no [DONE]: %+v %v", resp, err)
	}
	// Malformed tool arguments reach the loop as an object it can reject.
	f, srv = newFake(t, []conformance.Turn{{ToolCalls: []llm.ToolCall{{ID: "c", Name: "run_check", Input: json.RawMessage(`{"id": "x"`)}}, StopReason: llm.StopToolUse}})
	defer srv.Close()
	p = provider(t, f, srv.URL, llm.Config{})
	resp, err = llm.Complete(context.Background(), p, llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Text: "x"}}})
	if err != nil || len(resp.ToolCalls) != 1 || !json.Valid(resp.ToolCalls[0].Input) || !strings.Contains(string(resp.ToolCalls[0].Input), "_malformed") {
		t.Errorf("malformed arguments: %+v %v", resp, err)
	}
}

func TestModelTable(t *testing.T) {
	if m, ok := lookup("gpt-5-mini-2026-01-01"); !ok || m.prefix != "gpt-5-mini" {
		t.Errorf("longest prefix: %+v %v", m, ok)
	}
	if m, ok := lookup("gpt-5.6-luna"); !ok || m.prefix != "gpt-5.6-luna" || m.maxContext != 1050000 || !m.toolsNeedNone {
		t.Errorf("luna: %+v %v", m, ok)
	}
	if m, ok := lookup("gpt-5.6"); !ok || m.prefix != "gpt-5.6" {
		t.Errorf("gpt-5.6 alias must not match gpt-5: %+v %v", m, ok)
	}
	if m, ok := lookup("gpt-6-astra"); !ok || m.prefix != "gpt-6-astra" {
		t.Errorf("astra: %+v %v", m, ok)
	}
	if _, ok := lookup("llama-3"); ok {
		t.Error("unknown model matched")
	}
	if c := (modelInfo{}).cost(1, 0, 1); c != nil {
		t.Error("unpriced model produced a cost")
	}
}
