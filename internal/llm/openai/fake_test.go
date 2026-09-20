package openai

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/b87/scheck/internal/llm"
	"github.com/b87/scheck/internal/llm/conformance"
)

// fakeServer speaks enough of the chat completions protocol, streamed as
// server-sent events, to drive the conformance suite and the adapter's own
// tests. It records every request body it received.
type fakeServer struct {
	t      *testing.T
	turns  []conformance.Turn
	mu     sync.Mutex
	next   int
	bodies []map[string]any
	// hooks let a test make the server misbehave.
	rejectMaxCompletion bool // 400 on max_completion_tokens the first time
	rejectReasoning     bool // 400 on reasoning_effort
	rejectTools         bool // 400 unsupported tools
	status              int  // when set, every response is this status with an error body
	errorBody           string
	noDone              bool // end the stream without [DONE]
	auth                string
}

func newFake(t *testing.T, turns []conformance.Turn) (*fakeServer, *httptest.Server) {
	f := &fakeServer{t: t, turns: turns}
	return f, httptest.NewServer(http.HandlerFunc(f.handle))
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/chat/completions" || r.Method != http.MethodPost {
		http.Error(w, `{"error":{"message":"not found"}}`, http.StatusNotFound)
		return
	}
	f.mu.Lock()
	f.auth = r.Header.Get("Authorization")
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.bodies = append(f.bodies, body)
	idx := f.next
	f.mu.Unlock()

	fail := func(status int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"error":{"message":%q,"type":"invalid_request_error","code":"x"}}`, msg)
	}
	if f.status != 0 {
		fail(f.status, f.errorBody)
		return
	}
	if _, has := body["max_completion_tokens"]; has && f.rejectMaxCompletion {
		f.rejectMaxCompletion = false
		fail(400, "Unrecognized request argument supplied: max_completion_tokens")
		return
	}
	if _, has := body["reasoning_effort"]; has && f.rejectReasoning {
		fail(400, "Unrecognized request argument supplied: reasoning_effort")
		return
	}
	if _, has := body["tools"]; has && f.rejectTools {
		fail(400, "tools is not supported by this model")
		return
	}
	if idx >= len(f.turns) {
		fail(500, "no more scripted turns")
		return
	}
	f.mu.Lock()
	f.next++
	f.mu.Unlock()
	turn := f.turns[idx]
	switch turn.Fail {
	case llm.ErrContextOverflow:
		fail(400, "This model's maximum context length is 8192 tokens. However, your messages resulted in 9000 tokens.")
		return
	case llm.ErrAuth:
		fail(401, "Incorrect API key provided")
		return
	case llm.ErrTransport:
		fail(503, "The server is overloaded")
		return
	case llm.ErrUnsupported:
		fail(400, "tools is not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(200)
	fl, _ := w.(http.Flusher)
	emit := func(v any) {
		raw, _ := json.Marshal(v)
		fmt.Fprintf(w, "data: %s\n\n", raw)
		if fl != nil {
			fl.Flush()
		}
	}
	delta := func(d map[string]any, finish *string) map[string]any {
		return map[string]any{"id": "chatcmpl-1", "object": "chat.completion.chunk", "choices": []any{map[string]any{"index": 0, "delta": d, "finish_reason": finish}}}
	}
	// Text streams in two pieces; tool calls stream their arguments in
	// fragments, the way the real endpoint does.
	if turn.Text != "" {
		mid := len(turn.Text) / 2
		emit(delta(map[string]any{"role": "assistant", "content": turn.Text[:mid]}, nil))
		emit(delta(map[string]any{"content": turn.Text[mid:]}, nil))
	}
	for i, c := range turn.ToolCalls {
		args := string(c.Input)
		mid := len(args) / 2
		emit(delta(map[string]any{"tool_calls": []any{map[string]any{"index": i, "id": c.ID, "type": "function", "function": map[string]any{"name": c.Name, "arguments": args[:mid]}}}}, nil))
		emit(delta(map[string]any{"tool_calls": []any{map[string]any{"index": i, "function": map[string]any{"arguments": args[mid:]}}}}, nil))
	}
	finish := map[llm.StopReason]string{llm.StopEndTurn: "stop", llm.StopToolUse: "tool_calls", llm.StopMaxTokens: "length", llm.StopRefusal: "content_filter", llm.StopError: "weird"}[turn.StopReason]
	if finish == "" {
		finish = "stop"
		if len(turn.ToolCalls) > 0 {
			finish = "tool_calls"
		}
	}
	emit(delta(map[string]any{}, &finish))
	usage := map[string]any{"prompt_tokens": turn.Usage.Input, "completion_tokens": turn.Usage.Output, "prompt_tokens_details": map[string]any{"cached_tokens": turn.Usage.CacheRead}}
	emit(map[string]any{"id": "chatcmpl-1", "object": "chat.completion.chunk", "choices": []any{}, "usage": usage})
	if !f.noDone {
		fmt.Fprint(w, "data: [DONE]\n\n")
	}
}

func (f *fakeServer) lastBody() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bodies) == 0 {
		return nil
	}
	return f.bodies[len(f.bodies)-1]
}

func env(vars map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
	}
}

// harness builds the adapter against a fake server for the conformance
// suite. The script's limits are honoured through max_context, and a
// priced turn is simulated with a known model on the default-price path.
func harness(t *testing.T, s conformance.Script) llm.Provider {
	t.Helper()
	_, srv := newFake(t, s.Turns)
	t.Cleanup(srv.Close)
	cfg := llm.Config{Model: "test-model", BaseURL: srv.URL, MaxContext: s.Limits.MaxContext, Env: env(map[string]string{keyVar: "k"})}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.limits = s.Limits
	p.native = s.Native
	// The suite's priced turn: pretend this endpoint is priced with a flat
	// rate that reproduces the script's cost.
	for _, turn := range s.Turns {
		if turn.Usage.CostUSD != nil {
			p.priced = true
			p.info = modelInfo{inputUSD: *turn.Usage.CostUSD * 1e6 / float64(turn.Usage.Input), outputUSD: 0}
			p.info.cachedUSD = p.info.inputUSD
		}
	}
	return p
}

var _ = strings.TrimSpace
