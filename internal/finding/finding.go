// Package finding holds the compiled-in finding catalog (docs/SPEC.md §7.1),
// the posture rules that turn one fact into one finding (§7.5), and the
// evaluator that runs them over a phase 1 fact sheet.
//
// Nothing here executes anything. A rule reads the fact sheet the runner
// produced and nothing else: no target, no argv, no new command surface. A
// conclusion that needs a command the catalog does not have needs a catalog
// entry first, not a rule that goes looking.
package finding

import "github.com/b87/scheck/internal/check"

// Severity is the graded seriousness of a finding. Code owns it, never a
// model (docs/SPEC.md §7.2).
type Severity string

// Severities, ordered by Rank.
const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Rank orders severities; a higher rank is more serious.
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	case SevInfo:
		return 0
	}
	return -1
}

// AtLeast reports whether s is as serious as other.
func (s Severity) AtLeast(other Severity) bool { return s.Rank() >= other.Rank() }

// Threshold is the severity at which an open finding fails the run for a
// profile: `baseline` fails on medium, `hardened` on low (docs/SPEC.md §8).
// `info` findings stay visible and never set the exit code.
func Threshold(p check.Profile) Severity {
	if p == check.ProfileHardened {
		return SevLow
	}
	return SevMedium
}

// Remediation is text for the human. scheck never runs a command from here
// (docs/SPEC.md §7.3).
type Remediation struct {
	Summary  string   `json:"summary"`
	Commands []string `json:"commands,omitempty"`
	Caveat   string   `json:"caveat,omitempty"`
}

// Evidence is one check's contribution to a finding: the check id and the
// excerpt that matched, already redacted by the runner.
type Evidence struct {
	Check   string `json:"check"`
	Excerpt string `json:"excerpt"`
}

// Adjustment records one severity change and where it came from
// (docs/SPEC.md §6.3, §6.4): every change is attributed.
type Adjustment struct {
	Rule   string `json:"rule"`
	Source string `json:"source"`
	Delta  string `json:"delta"`
}

// Finding is what the report emits (docs/SPEC.md §7.3). A rule finding
// carries the Def's curated title, impact and remediation; the model may add
// evidence and notes in phase 2 but never replaces them (§7.5).
type Finding struct {
	ID           string       `json:"id"`
	Title        string       `json:"title"`
	Category     string       `json:"category"`
	SeverityBase Severity     `json:"severity_base"`
	Severity     Severity     `json:"severity"`
	Adjustments  []Adjustment `json:"adjustments"`
	Status       string       `json:"status"` // open | accepted
	// AcceptedReason is the operator's stated reason when Status is accepted.
	AcceptedReason string      `json:"accepted_reason,omitempty"`
	Source         string      `json:"source"` // rule | model
	Confidence     string      `json:"confidence"`
	Platform       string      `json:"platform"`
	Evidence       []Evidence  `json:"evidence"`
	Impact         string      `json:"impact"`
	Remediation    Remediation `json:"remediation"`
	// ContextNote is the model's attributed note on how operator context
	// bears on this finding; it never changes severity (§6.3).
	ContextNote string `json:"context_note,omitempty"`
	// Service is the listener a network finding is about, graded against
	// expected_services (§6.3).
	Service *ServiceRef `json:"service,omitempty"`
	// Custom marks a custom:<slug> finding: capped at medium, never
	// escalated, flagged for a reviewer to promote into the catalog (§7.1).
	Custom bool `json:"custom,omitempty"`
}

// Confidence levels (§7.3).
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Rank orders confidence levels.
func Rank(confidence string) int {
	switch confidence {
	case ConfidenceHigh:
		return 2
	case ConfidenceMedium:
		return 1
	case ConfidenceLow:
		return 0
	}
	return -1
}

// CategoryCustom is the category of a custom finding.
const CategoryCustom = "custom"

// Statuses a finding can carry.
const (
	StatusOpen     = "open"
	StatusAccepted = "accepted"
)

// Sources a finding can come from.
const (
	SourceRule  = "rule"
	SourceModel = "model"
)

// Open reports whether this finding counts towards the exit code.
func (f Finding) Open() bool { return f.Status == StatusOpen }
