package finding

import (
	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
)

// Facts are one host's facts as an engagement rule reads them
// (docs/spec/engagement.md, "Multi-fact rules"): the same usable or not
// decision the posture rules make, and only what survives a persisted
// envelope (status, reason, observation, parsed value), so a kept host is
// judged as the session that collected it judged it.
type Facts struct {
	sheet    *baseline.FactSheet
	disabled map[string]bool
}

// Fact is one check's usable fact.
type Fact struct {
	Check       string
	Observation string
	Parsed      any
	// Partial says the value is known to be incomplete: truncated, redacted,
	// or a typed record set with a line its parser did not recognise. A
	// rule may prove presence from it, never absence.
	Partial bool
}

// FactsOf are a fact sheet's facts, with the checks the operator disabled
// unusable.
func FactsOf(sheet *baseline.FactSheet, disabled []string) Facts {
	f := Facts{sheet: sheet, disabled: map[string]bool{}}
	for _, id := range disabled {
		f.disabled[id] = true
	}
	return f
}

// Platform is the host's platform, "" with no sheet.
func (f Facts) Platform() check.Platform {
	if f.sheet == nil {
		return ""
	}
	return f.sheet.Platform
}

// Fact is the check's fact, or why there is none a rule can read: the
// posture rules' reasons ("check-unavailable:command_missing").
func (f Facts) Fact(id string) (Fact, string) {
	if f.sheet == nil {
		return Fact{Check: id}, "check-not-run"
	}
	r, why := usable(id, f.disabled, f.sheet)
	if why != "" {
		return Fact{Check: id, Observation: r.Observation}, why
	}
	partial := r.Truncated || r.Redactions > 0
	if recs, ok := r.Parsed.(check.Records); ok && recs.Partial {
		partial = true
	}
	return Fact{Check: id, Observation: r.Observation, Parsed: r.Parsed, Partial: partial}, ""
}
