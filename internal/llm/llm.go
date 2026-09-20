// Package llm is the provider-neutral inference contract (docs/SPEC.md §5.1).
//
// Every adapter presents the full contract; the agent loop branches on
// nothing but Limits.MaxContext (§5.3). No provider SDK type crosses this
// package boundary, and the packages that consume it (agent, finding,
// report) compile with no provider dependency at all — the Makefile's
// depcheck target proves it.
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Role of a message.
type Role string

// Roles.
const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Tool is one callable exposed to the model. Schema is a JSON Schema
// (draft 2020-12 subset) for the tool's input.
type Tool struct {
	Name        string
	Description string
	Schema      json.RawMessage
}

// ToolCall is one call the model asked for.
type ToolCall struct {
	ID    string
	Name  string
	Input json.RawMessage
}

// ToolResult answers one ToolCall. IsError marks a result the model should
// correct from (unknown check id, denied path); it is never a silent drop.
type ToolResult struct {
	CallID  string
	Content string
	IsError bool
}

// Message is one conversation turn. Assistant turns carry ToolCalls; the
// user turn that answers them carries ToolResults.
type Message struct {
	Role        Role
	Text        string
	ToolCalls   []ToolCall
	ToolResults []ToolResult
}

// Block is one ordered piece of the system prompt. Cacheable marks a cache
// breakpoint after it: a hint an adapter may ignore.
type Block struct {
	Text      string
	Cacheable bool
}

// Effort is the reasoning budget, mapped per provider. It subsumes
// "reasoning on/off".
type Effort string

// Efforts.
const (
	EffortLow    Effort = "low"
	EffortMedium Effort = "medium"
	EffortHigh   Effort = "high"
	EffortMax    Effort = "max"
)

// ParseEffort validates a CLI or config spelling; "" is allowed and means
// the provider's default.
func ParseEffort(s string) (Effort, bool) {
	switch Effort(s) {
	case "", EffortLow, EffortMedium, EffortHigh, EffortMax:
		return Effort(s), true
	}
	return "", false
}

// Request is one model call.
type Request struct {
	Model     string
	System    []Block
	Messages  []Message
	Tools     []Tool
	MaxTokens int
	Effort    Effort
}

// StopReason says why the model stopped.
type StopReason string

// Stop reasons. Every adapter maps its provider's vocabulary onto these five.
const (
	StopEndTurn   StopReason = "end_turn"
	StopToolUse   StopReason = "tool_use"
	StopMaxTokens StopReason = "max_tokens"
	StopRefusal   StopReason = "refusal"
	StopError     StopReason = "error"
)

// Usage is normalized token accounting. CostUSD is nil when the provider has
// no price (docs/SPEC.md §5.5); tokens are always present.
type Usage struct {
	Input      int      `json:"input"`
	Output     int      `json:"output"`
	CacheRead  int      `json:"cache_read"`
	CacheWrite int      `json:"cache_write"`
	CostUSD    *float64 `json:"cost_usd"`
}

// Add accumulates u2 into u. Cost is summed only when every accumulated
// turn carried a price; one unpriced turn makes the total nil, so a partial
// price is never reported as the run's cost (docs/SPEC.md §5.5).
func (u *Usage) Add(u2 Usage) {
	fresh := u.Input == 0 && u.Output == 0 && u.CacheRead == 0 && u.CacheWrite == 0 && u.CostUSD == nil
	u.Input += u2.Input
	u.Output += u2.Output
	u.CacheRead += u2.CacheRead
	u.CacheWrite += u2.CacheWrite
	switch {
	case u2.CostUSD == nil:
		u.CostUSD = nil
	case fresh:
		c := *u2.CostUSD
		u.CostUSD = &c
	case u.CostUSD != nil:
		c := *u.CostUSD + *u2.CostUSD
		u.CostUSD = &c
	}
}

// Response is one completed model turn.
type Response struct {
	Text       string
	ToolCalls  []ToolCall
	StopReason StopReason
	Usage      Usage
}

// Limits is the one capability the loop must know about (docs/SPEC.md §5.3),
// plus whether the provider leaves the machine (§5.4).
type Limits struct {
	MaxContext int  `json:"max_context"`
	Local      bool `json:"local"`
}

// Native describes what the adapter maps to real provider features versus
// leaves unexercised. It is informational: it goes in the report header and
// into finding's confidence cap, never into agent control flow.
type Native struct {
	ToolCalling       bool `json:"tool_calling"`
	ParallelToolCalls bool `json:"parallel_tool_calls"`
	PromptCaching     bool `json:"prompt_caching"`
	Reasoning         bool `json:"reasoning"`
}

// Provider is the contract every adapter implements.
type Provider interface {
	Name() string
	Limits() Limits
	Native() Native
	Stream(ctx context.Context, r Request) (Stream, error)
}

// EventKind is what one streamed event carries.
type EventKind string

// Event kinds. A stream is any number of Text and ToolCall events followed
// by exactly one Done event carrying the assembled Response.
const (
	EventText     EventKind = "text"
	EventToolCall EventKind = "tool_call"
	EventDone     EventKind = "done"
)

// Event is one streamed increment.
type Event struct {
	Kind     EventKind
	Text     string    // EventText: a delta
	ToolCall *ToolCall // EventToolCall: a complete call
	Response *Response // EventDone: the whole turn
}

// Stream yields events until Done, then io.EOF.
type Stream interface {
	Recv() (Event, error)
	Close() error
}

// Complete drains a stream and returns the response. Providers do not
// implement it; there is one loop over events and this is it.
func Complete(ctx context.Context, p Provider, r Request) (Response, error) {
	s, err := p.Stream(ctx, r)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = s.Close() }()
	return Drain(s, nil)
}

// Drain reads a stream to its Done event, handing every event to observe
// when it is non-nil (so a CLI can show progress), and returns the response.
func Drain(s Stream, observe func(Event)) (Response, error) {
	for {
		ev, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return Response{}, errors.New("llm: stream ended without a done event")
		}
		if err != nil {
			return Response{}, err
		}
		if observe != nil {
			observe(ev)
		}
		if ev.Kind == EventDone {
			if ev.Response == nil {
				return Response{}, errors.New("llm: done event without a response")
			}
			return *ev.Response, nil
		}
	}
}

// ErrorKind classifies a provider failure so the loop can end a run honestly
// without knowing which provider it talked to.
type ErrorKind string

// Error kinds.
const (
	ErrContextOverflow ErrorKind = "context_overflow" // the provider rejected the request as too large
	ErrUnsupported     ErrorKind = "unsupported"      // the endpoint lacks a required feature (native tool calling)
	ErrAuth            ErrorKind = "auth"
	ErrTransport       ErrorKind = "transport"
	ErrResponse        ErrorKind = "response" // malformed or unexpected reply
)

// Error is a classified provider failure.
type Error struct {
	Kind ErrorKind
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Kind, e.Msg) }

// Errorf builds a classified error.
func Errorf(kind ErrorKind, format string, args ...any) error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, args...)}
}

// KindOf returns the classification of err, or "" for an unclassified one.
func KindOf(err error) ErrorKind {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Kind
	}
	return ""
}
