package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// WriteJSON renders the envelope as indented JSON.
func WriteJSON(w io.Writer, env Envelope) error { return WriteJSONEvidence(w, env, false) }

// WriteJSONEvidence adds only runner-filtered diagnostics to the rendered copy.
// Persisted envelopes remain compact; extraction and redaction still apply (§4.2).
func WriteJSONEvidence(w io.Writer, env Envelope, include bool) error {
	facts := make(map[string]any, len(env.Facts))
	type evidence struct {
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
	}
	for id, f := range env.Facts {
		var ev *evidence
		if include && (f.Attempted || f.Status == "ok") {
			ev = &evidence{f.Output, f.Stderr}
		}
		facts[id] = struct {
			Fact
			Evidence *evidence `json:"evidence,omitempty"`
		}{f, ev}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Envelope
		Facts map[string]any `json:"facts"`
	}{env, facts})
}

// summary is the one-line reading of a fact. Typed per-check summaries
// ("26 listening sockets") arrive with the typed parsers in M1.7; until then
// this is a shape-level reading of the parsed value, never a verdict.
func summary(f Fact) string {
	if f.Status != "ok" {
		if f.Reason == "" {
			return f.Status + ", no reason recorded"
		}
		return sanitize(f.Reason)
	}
	switch v := f.Parsed.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return "no output"
		}
		return firstLine(v)
	case []string:
		if len(v) == 0 {
			return "0 lines"
		}
		if len(v) == 1 {
			return "1 line: " + firstLine(v[0])
		}
		return fmt.Sprintf("%d lines: %s", len(v), firstLine(v[0]))
	case []any:
		return fmt.Sprintf("%d items", len(v))
	case map[string]string:
		return fmt.Sprintf("%d keys", len(v))
	case map[string]any:
		return fmt.Sprintf("%d keys", len(v))
	default:
		return "output recorded"
	}
}

func firstLine(s string) string {
	s = sanitize(strings.ReplaceAll(strings.TrimSpace(s), "\t", " "))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + " …"
	}
	if len([]rune(s)) > 120 {
		s = string([]rune(s)[:120]) + "…"
	}
	return s
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}
