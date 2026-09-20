// Package mock is the llm.Provider every non-live test uses (docs/SPEC.md
// §5.2): it replays a recorded transcript, one scripted turn per model call,
// and records every request it was given so a test can assert what the
// loop sent. It never touches the network.
package mock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/b87/scheck/internal/llm"
)

// Name is the provider name.
const Name = "mock"

func init() {
	llm.Register(llm.Info{
		Name:    Name,
		Summary: "replays a recorded transcript; tests only, no network",
	}, func(cfg llm.Config) (llm.Provider, error) {
		if cfg.Transcript == "" {
			return nil, errors.New("mock: --transcript FILE is required")
		}
		return Load(cfg.Transcript)
	})
}

// Transcript is the on-disk script: the provider's declared limits and
// native set, then one Turn per model call.
type Transcript struct {
	Limits llm.Limits `json:"limits"`
	Native llm.Native `json:"native"`
	Turns  []Turn     `json:"turns"`
}

// Turn is one scripted model reply.
type Turn struct {
	Text       string         `json:"text,omitempty"`
	ToolCalls  []Call         `json:"tool_calls,omitempty"`
	StopReason llm.StopReason `json:"stop_reason,omitempty"` // default: tool_use when calls exist, else end_turn
	Usage      *llm.Usage     `json:"usage,omitempty"`
	// Fail makes the call fail with this error kind instead of replying
	// (context_overflow, transport, ...), which is how a test drives the
	// loop's failure paths.
	Fail llm.ErrorKind `json:"fail,omitempty"`
	// Expect, when set, is checked against the request before replying; a
	// violation fails the call, so a transcript can assert what the loop
	// sent without the test reaching into the provider.
	Expect *Expect `json:"expect,omitempty"`
}

// Call is a scripted tool call. Input is kept as raw JSON so a transcript
// can send malformed input on purpose.
type Call struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// Expect are assertions over the request a turn answers.
type Expect struct {
	// ToolResults lists call ids whose results must be in the last message.
	ToolResults []string `json:"tool_results,omitempty"`
	// ErrorResults lists call ids whose results must be marked IsError.
	ErrorResults []string `json:"error_results,omitempty"`
	// Contains / NotContains are substrings of the whole serialized request.
	Contains    []string `json:"contains,omitempty"`
	NotContains []string `json:"not_contains,omitempty"`
}

// Provider replays a Transcript.
type Provider struct {
	t    Transcript
	mu   sync.Mutex
	next int
	reqs []llm.Request
}

// Load reads a transcript file.
func Load(path string) (*Provider, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mock: %w", err)
	}
	var t Transcript
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("mock: %s: %w", path, err)
	}
	return New(t), nil
}

// New builds a provider over an in-memory transcript. A zero MaxContext
// defaults to a generous window so a test that is not about limits never
// trips the guard by accident.
func New(t Transcript) *Provider {
	if t.Limits.MaxContext == 0 {
		t.Limits.MaxContext = 1 << 20
	}
	if t.Native == (llm.Native{}) {
		t.Native = llm.Native{ToolCalling: true, ParallelToolCalls: true}
	}
	return &Provider{t: t}
}

// Name implements llm.Provider.
func (p *Provider) Name() string { return Name }

// Limits implements llm.Provider.
func (p *Provider) Limits() llm.Limits { return p.t.Limits }

// Native implements llm.Provider.
func (p *Provider) Native() llm.Native { return p.t.Native }

// Requests returns every request received so far, in order.
func (p *Provider) Requests() []llm.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]llm.Request, len(p.reqs))
	copy(out, p.reqs)
	return out
}

// Stream implements llm.Provider: the next scripted turn, streamed as one
// text event, one event per tool call and a done event.
func (p *Provider) Stream(ctx context.Context, r llm.Request) (llm.Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.reqs = append(p.reqs, r)
	if p.next >= len(p.t.Turns) {
		p.mu.Unlock()
		return nil, llm.Errorf(llm.ErrResponse, "mock: transcript exhausted after %d turns", len(p.t.Turns))
	}
	turn := p.t.Turns[p.next]
	p.next++
	p.mu.Unlock()

	if turn.Fail != "" {
		return nil, llm.Errorf(turn.Fail, "mock: scripted failure")
	}
	if err := turn.Expect.check(r); err != nil {
		return nil, llm.Errorf(llm.ErrResponse, "mock: %v", err)
	}
	resp := llm.Response{Text: turn.Text, StopReason: turn.StopReason}
	if turn.Usage != nil {
		resp.Usage = *turn.Usage
	}
	for _, c := range turn.ToolCalls {
		resp.ToolCalls = append(resp.ToolCalls, llm.ToolCall{ID: c.ID, Name: c.Name, Input: c.Input})
	}
	if resp.StopReason == "" {
		resp.StopReason = llm.StopEndTurn
		if len(resp.ToolCalls) > 0 {
			resp.StopReason = llm.StopToolUse
		}
	}
	var events []llm.Event
	if resp.Text != "" {
		events = append(events, llm.Event{Kind: llm.EventText, Text: resp.Text})
	}
	for i := range resp.ToolCalls {
		c := resp.ToolCalls[i]
		events = append(events, llm.Event{Kind: llm.EventToolCall, ToolCall: &c})
	}
	events = append(events, llm.Event{Kind: llm.EventDone, Response: &resp})
	return &stream{events: events}, nil
}

type stream struct {
	events []llm.Event
	i      int
}

func (s *stream) Recv() (llm.Event, error) {
	if s.i >= len(s.events) {
		return llm.Event{}, io.EOF
	}
	ev := s.events[s.i]
	s.i++
	return ev, nil
}

func (s *stream) Close() error { return nil }

func (e *Expect) check(r llm.Request) error {
	if e == nil {
		return nil
	}
	var last llm.Message
	if len(r.Messages) > 0 {
		last = r.Messages[len(r.Messages)-1]
	}
	results := map[string]llm.ToolResult{}
	for _, res := range last.ToolResults {
		results[res.CallID] = res
	}
	for _, id := range e.ToolResults {
		if _, ok := results[id]; !ok {
			return fmt.Errorf("expected a tool result for call %q in the last message", id)
		}
	}
	for _, id := range e.ErrorResults {
		res, ok := results[id]
		if !ok || !res.IsError {
			return fmt.Errorf("expected an error result for call %q", id)
		}
	}
	if len(e.Contains) == 0 && len(e.NotContains) == 0 {
		return nil
	}
	ser := Serialize(r)
	for _, s := range e.Contains {
		if !strings.Contains(ser, s) {
			return fmt.Errorf("request does not contain %q", s)
		}
	}
	for _, s := range e.NotContains {
		if strings.Contains(ser, s) {
			return fmt.Errorf("request contains %q", s)
		}
	}
	return nil
}

// Serialize flattens a request to text for substring assertions: every
// system block, tool name and schema, message text, tool call and result.
func Serialize(r llm.Request) string {
	var b strings.Builder
	for _, blk := range r.System {
		b.WriteString(blk.Text)
		b.WriteString("\n")
	}
	for _, t := range r.Tools {
		b.WriteString(t.Name + "\n" + t.Description + "\n" + string(t.Schema) + "\n")
	}
	for _, m := range r.Messages {
		b.WriteString(string(m.Role) + ": " + m.Text + "\n")
		for _, c := range m.ToolCalls {
			b.WriteString(c.Name + " " + string(c.Input) + "\n")
		}
		for _, res := range m.ToolResults {
			b.WriteString(res.Content + "\n")
		}
	}
	return b.String()
}
