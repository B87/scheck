// Package report holds the run envelope (docs/SPEC.md §7.4) and its renderers.
package report

import (
	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/runner"
)

// Fact is one check's entry in the envelope's `facts` block.
type Fact struct {
	Observation string `json:"observation,omitempty"`
	Status      string `json:"status"` // ok | unavailable | denied
	ReasonCode  string `json:"reason_code,omitempty"`
	Attempted   bool   `json:"attempted"`
	Stderr      string `json:"-"`
	Reason      string `json:"reason,omitempty"`
	// Summary is the one-line human reading of this fact: the same string on
	// the screen, in the JSON and (from phase 2) in the model's prompt
	// (docs/SPEC.md §7.4, §7.6).
	Summary    string `json:"summary"`
	Parsed     any    `json:"parsed,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	Redactions int    `json:"redactions,omitempty"`
	Elevated   bool   `json:"elevated,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	// Output is the check's stdout after redaction and truncation
	// (docs/SPEC.md §4.2). It is deliberately not part of the JSON envelope,
	// which carries `parsed`, not raw bytes (§7.4); it exists so the text
	// renderer can show evidence at -vv or with --include-evidence. Default
	// JSON and persistence omit it. Extraction still minimizes this value.
	Output string `json:"-"`
}

// FactsFrom converts a fact sheet into the envelope shape.
func FactsFrom(sheet *baseline.FactSheet) map[string]Fact {
	out := make(map[string]Fact, len(sheet.Results))
	for id, r := range sheet.Results {
		f := factFrom(r, sheet.Platform)
		out[id] = f
	}
	return out
}

// Summarize is the one-line reading of a fact: what the check observed, or
// why it observed nothing. It is never a verdict — posture is the rules' job
// (docs/SPEC.md §7.5, §7.6).
func Summarize(c check.Check, f Fact) string {
	if f.Status != "ok" {
		if f.Reason == "" {
			return f.Status + ", no reason recorded"
		}
		return sanitize(f.Reason)
	}
	return sanitize(check.Summary(c, f.Parsed))
}

// Observation describes one invocation; Check is the request and RanAs the
// resolved catalog definition (possibly a metadata substitution). Argv exists
// only after typed binding; Attempted alone says whether execution was attempted.
type Observation struct {
	Fact
	Check      string            `json:"check"`
	RanAs      string            `json:"ran_as,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
	Argv       []string          `json:"argv,omitempty"`
	Occurrence int               `json:"occurrence"`
}

// observationsFrom builds the envelope's `observations` map. It carries
// each invocation's metadata, outcome and summary, not its parsed value:
// for a baseline check that would duplicate `facts`, and for a file read
// (a raw parser) it would be the whole capture, which default JSON and
// persistence omit by policy (docs/SPEC.md §7.4). Output stays on the
// struct for the opt-in evidence writer.
func observationsFrom(sheet *baseline.FactSheet) map[string]Observation {
	out := map[string]Observation{}
	for _, r := range sheet.Observations.All() {
		f := factFrom(r, sheet.Platform)
		f.Parsed = nil
		out[r.Observation] = Observation{Fact: f, Check: r.CheckID, RanAs: r.RanAs, Params: r.Params, Argv: r.Argv, Occurrence: r.Occurrence}
	}
	return out
}

func factFrom(r runner.Result, platform check.Platform) Fact {
	f := Fact{Observation: r.Observation, Status: string(r.Status), Reason: r.Reason, Truncated: r.Truncated,
		Redactions: r.Redactions, Elevated: r.Elevated, DurationMS: r.Duration.Milliseconds(),
		ReasonCode: r.ReasonCode, Attempted: r.Attempted, Output: r.Raw, Stderr: r.Stderr}
	if r.Status == runner.StatusOK {
		f.Parsed = r.Parsed
	}
	id := r.RanAs
	if id == "" {
		id = r.CheckID
	}
	c, _ := check.Lookup(id, platform)
	f.Summary = Summarize(c, f)
	return f
}
