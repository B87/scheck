package finding

import (
	"slices"
	"sort"

	"github.com/b87/scheck/internal/baseline"
	"github.com/b87/scheck/internal/check"
	"github.com/b87/scheck/internal/runner"
)

// Input is everything the evaluator reads. It is a fact sheet and the
// selection that produced it — no target, no runner, no way to execute.
type Input struct {
	Sheet    *baseline.FactSheet
	Profile  check.Profile
	Disabled []string // config disable_checks: selected rules become not_assessed
}

// Result is the deterministic half of the report: the findings the rules
// produced and the coverage record of every rule that was selected.
type Result struct {
	Findings    []Finding
	Assessments []Assessment
	// RuledOut lists the hypotheses the model checked and closed through
	// report_finding's verdict: ruled_out (docs/spec/model.md §8). Nothing here
	// is a finding; it is surfaced with the model's summary.
	RuledOut []RuledOut
}

// Evaluate runs every applicable posture rule over the fact sheet
// (docs/spec/host-collector.md §6.5). Rules outside the target's platform are omitted
// entirely; every other rule produces exactly one assessment, and only a
// matched one produces a finding.
func Evaluate(in Input) Result {
	res := Result{Findings: []Finding{}, Assessments: []Assessment{}}
	if in.Sheet == nil {
		return res
	}
	platform := in.Sheet.Platform
	disabled := map[string]bool{}
	for _, id := range in.Disabled {
		disabled[id] = true
	}
	byID := map[string]int{} // finding id -> index in res.Findings, for evidence merge
	for _, rule := range Rules() {
		if rule.Platform != check.Any && rule.Platform != platform {
			continue
		}
		a := Assessment{Finding: rule.Finding, Check: rule.Check, With: rule.With}
		v := evalRule(rule, platform, disabled, in.Sheet)
		a.Status, a.Reason = v.Status, v.Reason
		a.Observation = in.Sheet.Results[rule.Check].Observation
		if rule.With != "" {
			a.WithObservation = in.Sheet.Results[rule.With].Observation
		}
		res.Assessments = append(res.Assessments, a)
		if v.Status != Matched {
			continue
		}
		def, ok := Lookup(rule.Finding)
		if !ok {
			continue // ValidateRules makes this unreachable in a built binary
		}
		ev := Evidence{Observation: a.Observation, Check: rule.Check, Excerpt: v.Excerpt}
		evidence := []Evidence{ev}
		if rule.With != "" && v.WithExcerpt != "" {
			evidence = append(evidence, Evidence{Observation: in.Sheet.Results[rule.With].Observation,
				Check: rule.With, Excerpt: v.WithExcerpt})
		}
		if i, seen := byID[rule.Finding]; seen {
			for _, e := range evidence {
				res.Findings[i].Evidence = appendEvidence(res.Findings[i].Evidence, e)
			}
			continue
		}
		byID[rule.Finding] = len(res.Findings)
		res.Findings = append(res.Findings, Finding{
			ID: def.ID, Title: def.Title, Category: def.Category,
			SeverityBase: def.BaseSeverity, Severity: def.BaseSeverity,
			Adjustments: []Adjustment{}, Status: StatusOpen, Source: SourceRule,
			// A rule fires only on recognized evidence, so its confidence is
			// not a judgement call (docs/spec/host-collector.md §6.5).
			Confidence: ConfidenceHigh, Platform: string(platform),
			Evidence: evidence, Impact: def.Impact, Remediation: def.Remediation,
		})
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		if res.Findings[i].Severity != res.Findings[j].Severity {
			return res.Findings[i].Severity.Rank() > res.Findings[j].Severity.Rank()
		}
		return res.Findings[i].ID < res.Findings[j].ID
	})
	return res
}

// evalRule decides whether the rule could be assessed at all before its
// predicate ever sees a value. Applicability must be known: a platform gate
// or the catalog answers "not applicable"; a check that did not produce a
// usable fact answers "not assessed", never a pass (docs/spec/host-collector.md §6.5).
func evalRule(rule Rule, platform check.Platform, disabled map[string]bool, sheet *baseline.FactSheet) Verdict {
	c, ok := check.Lookup(rule.Check, platform)
	if !ok || !c.AppliesTo(platform) {
		return Verdict{Status: NotApplicable, Reason: "check-not-in-platform-catalog"}
	}
	r, why := usable(rule.Check, disabled, sheet)
	if why != "" {
		return notAssessed(why)
	}
	if rule.With == "" {
		return rule.When.Eval(r.Parsed)
	}
	jp, ok := rule.When.(JoinPredicate)
	if !ok {
		return notAssessed("rule-with-check-needs-join-predicate") // ValidateRules makes this unreachable
	}
	// The With check is read only when it gave a usable fact. Otherwise the
	// predicate decides from the first check alone, which can disprove (no
	// account without a password) but never fire; when it needed the second
	// check, the reason is that check's, so coverage names the right one.
	w, whyWith := usable(rule.With, disabled, sheet)
	if whyWith == "" {
		return jp.EvalWith(r.Parsed, w.Parsed)
	}
	v := jp.EvalWith(r.Parsed, nil)
	if v.Status == NotAssessed && v.Reason == ReasonWithUnread {
		v.Reason = ReasonWith + whyWith
	}
	return v
}

// usable returns a check's result, or why it gave no fact a rule can read:
// disabled, not run, denied or unavailable (docs/spec/host-collector.md §6.5).
func usable(id string, disabled map[string]bool, sheet *baseline.FactSheet) (runner.Result, string) {
	if disabled[id] {
		return runner.Result{}, "check-disabled-by-config"
	}
	r, ran := sheet.Results[id]
	if !ran {
		return r, "check-not-run"
	}
	switch r.Status {
	case runner.StatusDenied:
		return r, "check-denied:" + reasonCode(r)
	case runner.StatusUnavailable:
		return r, "check-unavailable:" + reasonCode(r)
	}
	return r, ""
}

func reasonCode(r runner.Result) string {
	if r.ReasonCode != "" {
		return r.ReasonCode
	}
	return "unknown"
}

func appendEvidence(have []Evidence, ev Evidence) []Evidence {
	if slices.Contains(have, ev) {
		return have
	}
	return append(have, ev)
}

// OpenAtOrAbove counts the open findings that meet a severity threshold; it
// is what decides exit 1 (docs/spec/host-collector.md §7).
func OpenAtOrAbove(fs []Finding, t Severity) int {
	n := 0
	for _, f := range fs {
		if f.Open() && f.Severity.AtLeast(t) {
			n++
		}
	}
	return n
}

// Tally is one severity's share of a finding list.
type Tally struct {
	Severity Severity
	Count    int
}

// CountBySeverity tallies findings for the report header, most serious first.
// Severities with no findings are left out.
func CountBySeverity(fs []Finding) []Tally {
	var out []Tally
	for _, s := range []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo} {
		n := 0
		for _, f := range fs {
			if f.Severity == s {
				n++
			}
		}
		if n > 0 {
			out = append(out, Tally{s, n})
		}
	}
	return out
}
