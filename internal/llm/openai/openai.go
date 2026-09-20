// Package openai is the openai-compatible llm.Provider (docs/SPEC.md §5.2):
// one adapter for OpenAI, vLLM, llama.cpp server, Groq, Together, LM Studio
// and OpenRouter, selected with --base-url and --model. It speaks the chat
// completions protocol with streaming and native tool calling over
// net/http; no SDK, and nothing of it crosses the llm boundary.
//
// Native tool calling is required in v1: an endpoint that rejects tools
// fails with an unsupported error, never with silent emulation (§5.3).
package openai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/b87/scheck/internal/llm"
)

// Name is the provider name.
const Name = "openai-compatible"

// DefaultBaseURL is OpenAI's endpoint (docs/SPEC.md §5.2).
const DefaultBaseURL = "https://api.openai.com/v1"

// keyVar is the environment variable the credential is read from (§9).
// It is the variable's name, never a value.
const keyVar = "OPENAI_API_KEY" //nolint:gosec // an environment variable name

func init() {
	llm.Register(llm.Info{
		Name:       Name,
		Summary:    "chat completions with native tool calling: OpenAI, vLLM, llama.cpp, Groq, Together, LM Studio, OpenRouter",
		Credential: keyVar,
	}, func(cfg llm.Config) (llm.Provider, error) { return New(cfg) })
}

// Provider is the adapter. It is safe for concurrent use.
type Provider struct {
	model   string
	baseURL string
	limits  llm.Limits
	info    modelInfo
	priced  bool
	env     func(string) (string, bool)
	client  *http.Client

	mu     sync.Mutex
	native llm.Native
	// legacyMaxTokens is set after an endpoint rejected
	// max_completion_tokens; older servers only know max_tokens.
	legacyMaxTokens bool
}

// New builds the adapter from configuration without any I/O. The model is
// required; the context window comes from max_context or the model table
// and an unknown window is a configuration error (§5.3). The credential is
// checked for presence only when the endpoint is OpenAI's; its value is
// read at request time.
func New(cfg llm.Config) (*Provider, error) {
	if cfg.Model == "" {
		return nil, errors.New("--model is required: the endpoint decides which models exist")
	}
	env := cfg.Env
	if env == nil {
		env = os.LookupEnv
	}
	base := cfg.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("base_url %q is not an absolute URL", base)
	}
	if u.User != nil {
		return nil, errors.New("base_url must not carry credentials; set " + keyVar)
	}
	base = strings.TrimRight(base, "/")
	info, known := lookup(cfg.Model)
	maxCtx := cfg.MaxContext
	if maxCtx == 0 && known {
		maxCtx = info.maxContext
	}
	if maxCtx <= 0 {
		return nil, fmt.Errorf("the context window of model %q is unknown; set max_context: or --max-context (docs/SPEC.md §5.3)", cfg.Model)
	}
	if base == DefaultBaseURL {
		if _, ok := env(keyVar); !ok {
			return nil, errors.New(keyVar + " is not set")
		}
	}
	p := &Provider{
		model: cfg.Model, baseURL: base, env: env,
		limits: llm.Limits{MaxContext: maxCtx, Local: false},
		info:   info, priced: known && base == DefaultBaseURL,
		client: &http.Client{Timeout: 10 * time.Minute},
		native: llm.Native{ToolCalling: true, ParallelToolCalls: true, PromptCaching: false, Reasoning: known && info.reasoning},
	}
	return p, nil
}

// Name implements llm.Provider.
func (p *Provider) Name() string { return Name }

// Limits implements llm.Provider.
func (p *Provider) Limits() llm.Limits { return p.limits }

// Native implements llm.Provider. PromptCaching is false because the adapter
// places no cache breakpoints: OpenAI caches long prefixes automatically and
// the hits show in usage.cache_read, but Block.Cacheable is not exercised.
// Reasoning flips to false if the endpoint rejects reasoning_effort.
func (p *Provider) Native() llm.Native {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.native
}

// Wire types of the chat completions protocol.
type wireMessage struct {
	Role       string         `json:"role"`
	Content    *string        `json:"content"`
	ToolCalls  []wireToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type wireToolCall struct {
	Index    *int         `json:"index,omitempty"`
	ID       string       `json:"id,omitempty"`
	Type     string       `json:"type,omitempty"`
	Function wireFunction `json:"function"`
}

type wireFunction struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type wireTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type wireRequest struct {
	Model               string         `json:"model"`
	Messages            []wireMessage  `json:"messages"`
	Tools               []wireTool     `json:"tools,omitempty"`
	ToolChoice          string         `json:"tool_choice,omitempty"`
	Stream              bool           `json:"stream"`
	StreamOptions       map[string]any `json:"stream_options,omitempty"`
	MaxCompletionTokens int            `json:"max_completion_tokens,omitempty"`
	MaxTokens           int            `json:"max_tokens,omitempty"`
	ReasoningEffort     string         `json:"reasoning_effort,omitempty"`
}

// encode maps the neutral request onto the wire (docs/SPEC.md §5.1). System
// blocks become one system message in order; tool results become `tool`
// messages; the output reservation is max_completion_tokens.
func (p *Provider) encode(r llm.Request, legacy bool, effort bool) wireRequest {
	w := wireRequest{Model: r.Model, Stream: true, StreamOptions: map[string]any{"include_usage": true}}
	if w.Model == "" {
		w.Model = p.model
	}
	if len(r.System) > 0 {
		var sys strings.Builder
		for i, b := range r.System {
			if i > 0 {
				sys.WriteString("\n\n")
			}
			sys.WriteString(b.Text)
		}
		s := sys.String()
		w.Messages = append(w.Messages, wireMessage{Role: "system", Content: &s})
	}
	for _, m := range r.Messages {
		switch m.Role {
		case llm.RoleAssistant:
			text := m.Text
			wm := wireMessage{Role: "assistant", Content: &text}
			if m.Text == "" {
				wm.Content = nil
			}
			for _, c := range m.ToolCalls {
				wm.ToolCalls = append(wm.ToolCalls, wireToolCall{ID: c.ID, Type: "function", Function: wireFunction{Name: c.Name, Arguments: string(c.Input)}})
			}
			w.Messages = append(w.Messages, wm)
		default:
			if m.Text != "" || len(m.ToolResults) == 0 {
				text := m.Text
				w.Messages = append(w.Messages, wireMessage{Role: "user", Content: &text})
			}
			for _, res := range m.ToolResults {
				content := res.Content
				w.Messages = append(w.Messages, wireMessage{Role: "tool", Content: &content, ToolCallID: res.CallID})
			}
		}
	}
	for _, t := range r.Tools {
		var wt wireTool
		wt.Type = "function"
		wt.Function.Name, wt.Function.Description, wt.Function.Parameters = t.Name, t.Description, t.Schema
		w.Tools = append(w.Tools, wt)
	}
	if len(w.Tools) > 0 {
		w.ToolChoice = "auto"
	}
	if r.MaxTokens > 0 {
		if legacy {
			w.MaxTokens = r.MaxTokens
		} else {
			w.MaxCompletionTokens = r.MaxTokens
		}
	}
	if effort && r.Effort != "" {
		w.ReasoningEffort = mapEffort(r.Effort)
	}
	return w
}

// mapEffort is the Effort mapping (docs/SPEC.md §5.1): the endpoint knows
// low|medium|high, so max is high.
func mapEffort(e llm.Effort) string {
	if e == llm.EffortMax {
		return "high"
	}
	return string(e)
}

// Stream implements llm.Provider.
func (p *Provider) Stream(ctx context.Context, r llm.Request) (llm.Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	legacy, effort := p.legacyMaxTokens, p.native.Reasoning
	p.mu.Unlock()
	for range 3 {
		resp, err := p.post(ctx, p.encode(r, legacy, effort))
		if err == nil {
			return newStream(resp.Body, p), nil
		}
		// Two capability differences the adapter absorbs (docs/SPEC.md §5.3)
		// rather than the loop: an endpoint that only knows max_tokens, and
		// one that rejects reasoning_effort. Each is retried once, and the
		// outcome is recorded in Native so the report never claims a feature
		// that was not exercised.
		if bad, ok := errors.AsType[*badRequest](err); ok {
			switch {
			case !legacy && bad.mentions("max_completion_tokens"):
				legacy = true
				p.mu.Lock()
				p.legacyMaxTokens = true
				p.mu.Unlock()
				continue
			case effort && bad.mentions("reasoning_effort", "reasoning"):
				effort = false
				p.mu.Lock()
				p.native.Reasoning = false
				p.mu.Unlock()
				continue
			}
		}
		return nil, err
	}
	return nil, llm.Errorf(llm.ErrTransport, "request rejected after retries")
}

// badRequest is a 400 the adapter may be able to rephrase.
type badRequest struct {
	body string
	err  error
}

func (b *badRequest) Error() string { return b.err.Error() }
func (b *badRequest) Unwrap() error { return b.err }
func (b *badRequest) mentions(words ...string) bool {
	low := strings.ToLower(b.body)
	for _, w := range words {
		if strings.Contains(low, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

func (p *Provider) post(ctx context.Context, w wireRequest) (*http.Response, error) {
	body, err := json.Marshal(w)
	if err != nil {
		return nil, llm.Errorf(llm.ErrResponse, "encode request: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, llm.Errorf(llm.ErrTransport, "%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if key, ok := p.env(keyVar); ok && key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, llm.Errorf(llm.ErrTransport, "%v", err)
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	msg := errorMessage(raw)
	return nil, classify(resp.StatusCode, msg, string(raw))
}

// errorMessage pulls the message out of an OpenAI-style error body.
func errorMessage(raw []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
			Code    any    `json:"code"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error.Message != "" {
		if e.Error.Code != nil {
			return fmt.Sprintf("%s (%v)", e.Error.Message, e.Error.Code)
		}
		return e.Error.Message
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// classify maps an HTTP failure onto llm.ErrorKind (docs/SPEC.md §5.1).
func classify(status int, msg, body string) error {
	low := strings.ToLower(msg + " " + body)
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return llm.Errorf(llm.ErrAuth, "HTTP %d: %s", status, msg)
	case strings.Contains(low, "context_length_exceeded") || strings.Contains(low, "maximum context length") ||
		strings.Contains(low, "context window") || strings.Contains(low, "too many tokens") || status == http.StatusRequestEntityTooLarge:
		return llm.Errorf(llm.ErrContextOverflow, "HTTP %d: %s", status, msg)
	case status == http.StatusBadRequest && (strings.Contains(low, "tool") || strings.Contains(low, "function")) &&
		(strings.Contains(low, "not support") || strings.Contains(low, "unsupported") || strings.Contains(low, "unknown parameter") || strings.Contains(low, "unrecognized")):
		return llm.Errorf(llm.ErrUnsupported, "native tool calling is required and this endpoint rejected it: %s", msg)
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		return &badRequest{body: body, err: llm.Errorf(llm.ErrResponse, "HTTP %d: %s", status, msg)}
	default:
		return llm.Errorf(llm.ErrTransport, "HTTP %d: %s", status, msg)
	}
}

// stream decodes server-sent events into llm.Events. Text deltas are
// emitted as they arrive; tool calls are assembled by index and emitted
// once the reply is complete, since their arguments stream in fragments.
type stream struct {
	body    io.ReadCloser
	scanner *bufio.Scanner
	p       *Provider
	pending []llm.Event
	done    bool
	text    strings.Builder
	calls   map[int]*wireToolCall
	order   []int
	finish  string
	usage   llm.Usage
	sawUse  bool
}

func newStream(body io.ReadCloser, p *Provider) *stream {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	return &stream{body: body, scanner: sc, p: p, calls: map[int]*wireToolCall{}}
}

func (s *stream) Close() error { return s.body.Close() }

func (s *stream) Recv() (llm.Event, error) {
	for {
		if len(s.pending) > 0 {
			ev := s.pending[0]
			s.pending = s.pending[1:]
			return ev, nil
		}
		if s.done {
			return llm.Event{}, io.EOF
		}
		if !s.scanner.Scan() {
			if err := s.scanner.Err(); err != nil {
				return llm.Event{}, llm.Errorf(llm.ErrTransport, "stream: %v", err)
			}
			// The server closed without [DONE]; treat what we have as the
			// reply if a finish reason arrived, else it is a broken stream.
			if s.finish == "" {
				return llm.Event{}, llm.Errorf(llm.ErrResponse, "stream ended before the reply finished")
			}
			s.finishUp()
			continue
		}
		line := s.scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			s.finishUp()
			continue
		}
		if err := s.chunk([]byte(data)); err != nil {
			return llm.Event{}, err
		}
	}
}

type wireChunk struct {
	Choices []struct {
		Delta        wireMessage `json:"delta"`
		FinishReason *string     `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens        int `json:"prompt_tokens"`
		CompletionTokens    int `json:"completion_tokens"`
		PromptTokensDetails *struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (s *stream) chunk(data []byte) error {
	var c wireChunk
	if err := json.Unmarshal(data, &c); err != nil {
		return llm.Errorf(llm.ErrResponse, "stream: malformed chunk: %v", err)
	}
	if c.Error != nil {
		return classify(http.StatusBadRequest, c.Error.Message, c.Error.Message)
	}
	if c.Usage != nil {
		s.usage = llm.Usage{Input: c.Usage.PromptTokens, Output: c.Usage.CompletionTokens}
		if c.Usage.PromptTokensDetails != nil {
			s.usage.CacheRead = c.Usage.PromptTokensDetails.CachedTokens
		}
		s.sawUse = true
	}
	for _, ch := range c.Choices {
		if ch.Delta.Content != nil && *ch.Delta.Content != "" {
			s.text.WriteString(*ch.Delta.Content)
			s.pending = append(s.pending, llm.Event{Kind: llm.EventText, Text: *ch.Delta.Content})
		}
		for _, tc := range ch.Delta.ToolCalls {
			idx := len(s.order)
			if tc.Index != nil {
				idx = *tc.Index
			}
			cur, ok := s.calls[idx]
			if !ok {
				cur = &wireToolCall{}
				s.calls[idx] = cur
				s.order = append(s.order, idx)
			}
			if tc.ID != "" {
				cur.ID = tc.ID
			}
			if tc.Function.Name != "" {
				cur.Function.Name = tc.Function.Name
			}
			cur.Function.Arguments += tc.Function.Arguments
		}
		if ch.FinishReason != nil && *ch.FinishReason != "" {
			s.finish = *ch.FinishReason
		}
	}
	return nil
}

// finishUp assembles the response and queues the tool-call and done events.
func (s *stream) finishUp() {
	if s.done {
		return
	}
	s.done = true
	resp := llm.Response{Text: s.text.String(), Usage: s.usage}
	sort.Ints(s.order)
	for _, idx := range s.order {
		c := s.calls[idx]
		args := strings.TrimSpace(c.Function.Arguments)
		if args == "" {
			args = "{}"
		}
		if !json.Valid([]byte(args)) {
			// A malformed argument string is still handed to the loop, which
			// answers the model with an error result it can correct from.
			args = string(llm.MustJSON(map[string]string{"_malformed": c.Function.Arguments}))
		}
		call := llm.ToolCall{ID: c.ID, Name: c.Function.Name, Input: json.RawMessage(args)}
		if call.ID == "" {
			call.ID = fmt.Sprintf("call_%d", idx)
		}
		resp.ToolCalls = append(resp.ToolCalls, call)
		cc := call
		s.pending = append(s.pending, llm.Event{Kind: llm.EventToolCall, ToolCall: &cc})
	}
	switch s.finish {
	case "tool_calls", "function_call":
		resp.StopReason = llm.StopToolUse
	case "length":
		resp.StopReason = llm.StopMaxTokens
	case "content_filter":
		resp.StopReason = llm.StopRefusal
	case "stop", "":
		resp.StopReason = llm.StopEndTurn
		if len(resp.ToolCalls) > 0 {
			resp.StopReason = llm.StopToolUse
		}
	default:
		resp.StopReason = llm.StopError
	}
	if s.p.priced && s.sawUse {
		resp.Usage.CostUSD = s.p.info.cost(resp.Usage.Input, resp.Usage.CacheRead, resp.Usage.Output)
	}
	s.pending = append(s.pending, llm.Event{Kind: llm.EventDone, Response: &resp})
}
