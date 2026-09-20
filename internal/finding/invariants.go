package finding

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/b87/scheck/internal/check"
)

// Violation is one failed rule invariant, named so a test failure says which
// rule was broken rather than that something is wrong.
type Violation struct {
	Subject string // the rule ("finding via check") or the finding id
	Rule    string // the invariant name
	Detail  string
}

func (v Violation) String() string { return v.Subject + ": " + v.Rule + ": " + v.Detail }

// Invariant rule names (docs/SPEC.md §7.5, last bullet).
const (
	RuleUnknownFinding = "rule-finding-not-in-catalog"
	RuleUnknownCheck   = "rule-check-not-in-catalog"
	RuleParserMismatch = "predicate-parser-mismatch"
	RuleNoPredicate    = "rule-without-predicate"
	RuleBadRegexp      = "rule-bad-regexp"
	RuleDefIncomplete  = "finding-def-incomplete"
	RuleDefSeverity    = "finding-def-unknown-severity"
	RuleDefCategory    = "finding-def-unknown-category"
)

// Categories a Def may carry (docs/SPEC.md §7.1), plus the two the grader
// and custom findings introduce.
var Categories = []string{
	CategoryRemoteAccess, CategoryNetwork, "accounts", "privesc", "integrity", "updates",
	"persistence", "logging", "fs", "disk", "time", CategoryGovernance, CategoryCustom,
}

func knownCategory(c string) bool {
	return slices.Contains(Categories, c)
}

// regexpFields collects every pattern a predicate will compile at evaluation
// time, so a malformed one fails the invariants test rather than a run.
func regexpFields(p Predicate) []string {
	switch v := p.(type) {
	case RawMatch:
		return []string{v.Regexp, v.Requires}
	case AnyLine:
		return []string{v.Regexp}
	case FieldOutside:
		return []string{v.Recognize}
	}
	return nil
}

// ValidateRules applies the §7.5 invariants over the compiled-in tables:
// every Rule.Finding is a Def, every Rule.Check is a catalog id for the
// rule's platform, and the predicate kind matches the check's parser. It
// never panics on a broken entry; that is the point.
func ValidateRules() []Violation {
	var out []Violation
	for _, d := range Defs() {
		if !knownCategory(d.Category) {
			out = append(out, Violation{d.ID, RuleDefCategory, fmt.Sprintf("category %q", d.Category)})
		}
		if d.Title == "" || d.Impact == "" || d.Category == "" || d.Remediation.Summary == "" {
			out = append(out, Violation{d.ID, RuleDefIncomplete,
				"a rule finding has no model to write its text, so title, category, impact and remediation are required"})
		}
		if d.BaseSeverity.Rank() < 0 {
			out = append(out, Violation{d.ID, RuleDefSeverity, fmt.Sprintf("severity %q", d.BaseSeverity)})
		}
	}
	for _, r := range Rules() {
		name := r.Finding + " via " + r.Check
		if _, ok := Lookup(r.Finding); !ok {
			out = append(out, Violation{name, RuleUnknownFinding, r.Finding})
		}
		if r.When == nil {
			out = append(out, Violation{name, RuleNoPredicate, "no predicate"})
			continue
		}
		for _, re := range regexpFields(r.When) {
			if re == "" {
				continue
			}
			if _, err := regexp.Compile(re); err != nil {
				out = append(out, Violation{name, RuleBadRegexp, fmt.Sprintf("%q: %v", re, err)})
			}
		}
		platforms := []check.Platform{r.Platform}
		if r.Platform == check.Any {
			platforms = []check.Platform{check.Linux, check.MacOS}
		}
		for _, p := range platforms {
			c, ok := check.Lookup(r.Check, p)
			if !ok {
				out = append(out, Violation{name, RuleUnknownCheck,
					fmt.Sprintf("%s is not a catalog id on %s", r.Check, p)})
				continue
			}
			if !r.When.Accepts(c.Parser) {
				out = append(out, Violation{name, RuleParserMismatch,
					fmt.Sprintf("predicate %s cannot read a %q fact (%s on %s)", r.When, c.Parser, r.Check, p)})
			}
		}
	}
	return out
}
