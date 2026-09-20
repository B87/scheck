// Package conformance is the one table every llm.Provider must pass
// (docs/SPEC.md §11): tool-call round trip, error results, several calls in
// one turn, every StopReason, MaxTokens truncation, usage normalization and
// Limits reporting. An adapter's own test supplies a Harness that turns a
// Script into a provider — a transcript for mock, a fake HTTP server for
// openai-compatible — and the scenarios are the same for both. That is the
// point: the loop must not be able to tell them apart.
package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/b87/scheck/internal/llm"
)

// Turn is one scripted model reply, provider-neutral.
type Turn struct {
	Text       string
	ToolCalls  []llm.ToolCall
	StopReason llm.StopReason
	Usage      llm.Usage
	Fail       llm.ErrorKind // when set, the call fails with this kind
}

// Script is what a provider will say, turn by turn, plus what it declares.
type Script struct {
	Limits llm.Limits
	Native llm.Native
	Turns  []Turn
}

// Harness builds a provider that will follow the script.
type Harness func(t *testing.T, s Script) llm.Provider

var priced = 0.0123

func baseScript(turns ...Turn) Script {
	return Script{Limits: llm.Limits{MaxContext: 128000}, Native: llm.Native{ToolCalling: true, ParallelToolCalls: true}, Turns: turns}
}

func request(msgs ...llm.Message) llm.Request {
	return llm.Request{
		Model:     "conformance-model",
		System:    []llm.Block{{Text: "You are a test.", Cacheable: true}},
		Tools:     []llm.Tool{{Name: "run_check", Description: "run a check", Schema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`)}},
		Messages:  append([]llm.Message{{Role: llm.RoleUser, Text: "begin"}}, msgs...),
		MaxTokens: 256,
	}
}

// Run executes the whole table against the harness.
func Run(t *testing.T, name string, h Harness) {
	t.Helper()
	t.Run(name+"/limits-and-native", func(t *testing.T) {
		s := baseScript(Turn{Text: "hi"})
		s.Limits = llm.Limits{MaxContext: 4096, Local: true}
		s.Native = llm.Native{ToolCalling: true}
		p := h(t, s)
		if p.Name() == "" {
			t.Error("empty provider name")
		}
		if got := p.Limits(); got != s.Limits {
			t.Errorf("Limits() = %+v, want %+v", got, s.Limits)
		}
		if got := p.Native(); got != s.Native {
			t.Errorf("Native() = %+v, want %+v", got, s.Native)
		}
	})

	t.Run(name+"/tool-call-round-trip", func(t *testing.T) {
		call := llm.ToolCall{ID: "call_1", Name: "run_check", Input: json.RawMessage(`{"id":"sshd.config"}`)}
		p := h(t, baseScript(
			Turn{Text: "checking", ToolCalls: []llm.ToolCall{call}, StopReason: llm.StopToolUse},
			Turn{Text: "done", StopReason: llm.StopEndTurn},
		))
		ctx := context.Background()
		r1, err := llm.Complete(ctx, p, request())
		if err != nil {
			t.Fatal(err)
		}
		if r1.StopReason != llm.StopToolUse || len(r1.ToolCalls) != 1 {
			t.Fatalf("turn 1: %+v", r1)
		}
		if got := r1.ToolCalls[0]; got.ID != call.ID || got.Name != call.Name || !jsonEqual(got.Input, call.Input) {
			t.Fatalf("tool call round trip: %+v want %+v", got, call)
		}
		r2, err := llm.Complete(ctx, p, request(
			llm.Message{Role: llm.RoleAssistant, Text: r1.Text, ToolCalls: r1.ToolCalls},
			llm.Message{Role: llm.RoleUser, ToolResults: []llm.ToolResult{{CallID: call.ID, Content: `{"status":"ok"}`}}},
		))
		if err != nil {
			t.Fatal(err)
		}
		if r2.StopReason != llm.StopEndTurn || r2.Text != "done" || len(r2.ToolCalls) != 0 {
			t.Fatalf("turn 2: %+v", r2)
		}
	})

	t.Run(name+"/error-result-is-accepted", func(t *testing.T) {
		call := llm.ToolCall{ID: "call_e", Name: "run_check", Input: json.RawMessage(`{"id":"nope"}`)}
		p := h(t, baseScript(
			Turn{ToolCalls: []llm.ToolCall{call}, StopReason: llm.StopToolUse},
			Turn{Text: "corrected", StopReason: llm.StopEndTurn},
		))
		ctx := context.Background()
		if _, err := llm.Complete(ctx, p, request()); err != nil {
			t.Fatal(err)
		}
		r2, err := llm.Complete(ctx, p, request(
			llm.Message{Role: llm.RoleAssistant, ToolCalls: []llm.ToolCall{call}},
			llm.Message{Role: llm.RoleUser, ToolResults: []llm.ToolResult{{CallID: call.ID, Content: "unknown check id", IsError: true}}},
		))
		if err != nil || r2.Text != "corrected" {
			t.Fatalf("after an error result: %+v %v", r2, err)
		}
	})

	t.Run(name+"/multiple-calls-one-turn", func(t *testing.T) {
		calls := []llm.ToolCall{
			{ID: "a", Name: "run_check", Input: json.RawMessage(`{"id":"x"}`)},
			{ID: "b", Name: "run_check", Input: json.RawMessage(`{"id":"y"}`)},
			{ID: "c", Name: "run_check", Input: json.RawMessage(`{"id":"z"}`)},
		}
		p := h(t, baseScript(Turn{ToolCalls: calls, StopReason: llm.StopToolUse}))
		s, err := p.Stream(context.Background(), request())
		if err != nil {
			t.Fatal(err)
		}
		var streamed []llm.ToolCall
		resp, err := llm.Drain(s, func(ev llm.Event) {
			if ev.Kind == llm.EventToolCall {
				streamed = append(streamed, *ev.ToolCall)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(streamed) != 3 || len(resp.ToolCalls) != 3 {
			t.Fatalf("streamed %d, response %d calls", len(streamed), len(resp.ToolCalls))
		}
		for i, c := range calls {
			if resp.ToolCalls[i].ID != c.ID || streamed[i].ID != c.ID || !jsonEqual(resp.ToolCalls[i].Input, c.Input) {
				t.Errorf("call %d: %+v / %+v want %+v", i, resp.ToolCalls[i], streamed[i], c)
			}
		}
		if _, err := s.Recv(); !errors.Is(err, io.EOF) {
			t.Errorf("after done: %v, want EOF", err)
		}
	})

	t.Run(name+"/stop-reasons", func(t *testing.T) {
		for _, reason := range []llm.StopReason{llm.StopEndTurn, llm.StopMaxTokens, llm.StopRefusal} {
			p := h(t, baseScript(Turn{Text: "partial", StopReason: reason}))
			resp, err := llm.Complete(context.Background(), p, request())
			if err != nil {
				t.Fatalf("%s: %v", reason, err)
			}
			if resp.StopReason != reason {
				t.Errorf("stop %s mapped to %s", reason, resp.StopReason)
			}
			if resp.Text != "partial" {
				t.Errorf("%s: text %q lost", reason, resp.Text)
			}
		}
		p := h(t, baseScript(Turn{ToolCalls: []llm.ToolCall{{ID: "t", Name: "run_check", Input: json.RawMessage(`{}`)}}, StopReason: llm.StopToolUse}))
		resp, err := llm.Complete(context.Background(), p, request())
		if err != nil || resp.StopReason != llm.StopToolUse {
			t.Errorf("tool_use: %+v %v", resp, err)
		}
	})

	t.Run(name+"/provider-errors-are-classified", func(t *testing.T) {
		for _, kind := range []llm.ErrorKind{llm.ErrContextOverflow, llm.ErrTransport, llm.ErrAuth} {
			p := h(t, baseScript(Turn{Fail: kind}))
			_, err := llm.Complete(context.Background(), p, request())
			if err == nil {
				t.Fatalf("%s: no error", kind)
			}
			if got := llm.KindOf(err); got != kind {
				t.Errorf("%s classified as %q (%v)", kind, got, err)
			}
		}
	})

	t.Run(name+"/max-tokens-truncation", func(t *testing.T) {
		p := h(t, baseScript(Turn{Text: "cut off mid", StopReason: llm.StopMaxTokens, Usage: llm.Usage{Input: 10, Output: 256}}))
		r := request()
		r.MaxTokens = 256
		resp, err := llm.Complete(context.Background(), p, r)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StopReason != llm.StopMaxTokens || resp.Usage.Output != 256 {
			t.Errorf("truncation: %+v", resp)
		}
	})

	t.Run(name+"/usage-normalization", func(t *testing.T) {
		u := llm.Usage{Input: 1200, Output: 34, CacheRead: 1000, CacheWrite: 200, CostUSD: &priced}
		p := h(t, baseScript(Turn{Text: "ok", Usage: u}))
		resp, err := llm.Complete(context.Background(), p, request())
		if err != nil {
			t.Fatal(err)
		}
		if resp.Usage.Input != u.Input || resp.Usage.Output != u.Output || resp.Usage.CacheRead != u.CacheRead {
			t.Errorf("usage %+v want %+v", resp.Usage, u)
		}
		// cache_write exists only where the adapter places cache breakpoints
		// (Native.PromptCaching); a protocol without the concept reports 0,
		// never a guess.
		if p.Native().PromptCaching && resp.Usage.CacheWrite != u.CacheWrite {
			t.Errorf("cache_write %d want %d", resp.Usage.CacheWrite, u.CacheWrite)
		}
		if !p.Native().PromptCaching && resp.Usage.CacheWrite != 0 {
			t.Errorf("cache_write %d reported without prompt caching", resp.Usage.CacheWrite)
		}
		if resp.Usage.CostUSD == nil || *resp.Usage.CostUSD != priced {
			t.Errorf("cost %v want %v", resp.Usage.CostUSD, priced)
		}
		unpriced := h(t, baseScript(Turn{Text: "ok", Usage: llm.Usage{Input: 5, Output: 1}}))
		resp, err = llm.Complete(context.Background(), unpriced, request())
		if err != nil {
			t.Fatal(err)
		}
		if resp.Usage.CostUSD != nil {
			t.Errorf("unpriced turn reported cost %v", *resp.Usage.CostUSD)
		}
	})

	t.Run(name+"/context-cancel", func(t *testing.T) {
		p := h(t, baseScript(Turn{Text: "never"}))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := llm.Complete(ctx, p, request()); err == nil {
			t.Error("a cancelled context still produced a reply")
		}
	})
}

func jsonEqual(a, b json.RawMessage) bool {
	var va, vb any
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return string(a) == string(b)
	}
	ja, _ := json.Marshal(va)
	jb, _ := json.Marshal(vb)
	return string(ja) == string(jb)
}
