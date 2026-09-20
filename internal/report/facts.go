// Package report holds the run envelope (docs/SPEC.md §7.4) and its renderers.
package report

import (
	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/runner"
)

// Fact is one check's entry in the envelope's `facts` block.
type Fact struct {
	Status     string `json:"status"` // ok | unavailable | denied
	ReasonCode string `json:"reason_code,omitempty"`
	Attempted  bool   `json:"attempted"`
	Stderr     string `json:"-"`
	Reason     string `json:"reason,omitempty"`
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
		f := Fact{Status: string(r.Status), Reason: r.Reason, Truncated: r.Truncated,
			Redactions: r.Redactions, Elevated: r.Elevated, DurationMS: r.Duration.Milliseconds()}
		f.ReasonCode, f.Attempted = r.ReasonCode, r.Attempted
		f.Output, f.Stderr = r.Raw, r.Stderr
		if r.Status == runner.StatusOK {
			f.Parsed = r.Parsed
		}
		out[id] = f
	}
	return out
}
