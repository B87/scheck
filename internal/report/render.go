package report

import (
	"encoding/json"
	"io"
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
	observations := make(map[string]any, len(env.Observations))
	for ref, o := range env.Observations {
		var ev *evidence
		if include && (o.Attempted || o.Status == "ok") {
			ev = &evidence{o.Output, o.Stderr}
		}
		observations[ref] = struct {
			Observation
			Evidence *evidence `json:"evidence,omitempty"`
		}{o, ev}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Envelope
		Facts        map[string]any `json:"facts"`
		Observations map[string]any `json:"observations"`
	}{env, facts, observations})
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}
