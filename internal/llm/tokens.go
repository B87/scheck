package llm

import (
	"encoding/json"
	"fmt"
)

// Token accounting lives here, not in the agent loop (docs/SPEC.md §5.3):
// the loop asks whether a request fits and never learns how a request is
// serialized. The estimate is a documented conservative bound rather than a
// per-model tokenizer, so it errs on the side of refusing to send.
//
// Bound: every 3 bytes of text is one token (English prose averages about
// 4 bytes per token; code, JSON and command output run denser, so 3 is the
// safe side), plus fixed framing per message, per tool call or result, and
// per tool definition, plus a request-level allowance for the provider's own
// wrapping.
const (
	bytesPerToken     = 3
	perMessageTokens  = 8  // role, delimiters
	perToolCallTokens = 12 // id, name, wrapping
	perToolDefTokens  = 24 // name, description framing, schema wrapping
	requestFraming    = 64 // provider envelope
)

// Estimate is the conservative token count of the whole serialized request:
// system blocks, tool schemas, every message and tool result, and framing.
// It never counts the output reservation; Fit adds that.
func Estimate(r Request) int {
	n := requestFraming
	for _, b := range r.System {
		n += tokensOf(len(b.Text)) + perMessageTokens
	}
	for _, t := range r.Tools {
		n += tokensOf(len(t.Name)+len(t.Description)+len(t.Schema)) + perToolDefTokens
	}
	for _, m := range r.Messages {
		n += perMessageTokens + tokensOf(len(m.Text))
		for _, c := range m.ToolCalls {
			n += perToolCallTokens + tokensOf(len(c.ID)+len(c.Name)+len(c.Input))
		}
		for _, res := range m.ToolResults {
			n += perToolCallTokens + tokensOf(len(res.CallID)+len(res.Content))
		}
	}
	return n
}

func tokensOf(bytes int) int { return (bytes + bytesPerToken - 1) / bytesPerToken }

// Fit is the answer to "may this request be sent?".
type Fit struct {
	Estimated  int // tokens in the serialized request
	Reserved   int // output allowance (Request.MaxTokens)
	MaxContext int
}

// OK reports whether the request plus its output reservation fits.
func (f Fit) OK() bool { return f.Estimated+f.Reserved <= f.MaxContext }

func (f Fit) String() string {
	return fmt.Sprintf("request ~%d tokens + %d reserved for output > %d context limit",
		f.Estimated, f.Reserved, f.MaxContext)
}

// CheckFit decides, before any bytes leave the machine, whether the entire
// request plus its output reservation fits the provider's context (docs/SPEC.md
// §5.3). An unknown limit is a configuration error, never unlimited space.
func CheckFit(r Request, l Limits) (Fit, error) {
	if l.MaxContext <= 0 {
		return Fit{}, Errorf(ErrUnsupported, "context limit unknown: set max_context for this model")
	}
	f := Fit{Estimated: Estimate(r), Reserved: r.MaxTokens, MaxContext: l.MaxContext}
	if !f.OK() {
		return f, Errorf(ErrContextOverflow, "%s", f)
	}
	return f, nil
}

// MustJSON marshals v for a tool schema or input; a marshal failure of a
// compiled-in value is a programming error.
func MustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
